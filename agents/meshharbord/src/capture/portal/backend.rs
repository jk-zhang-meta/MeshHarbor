// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-45 P3c-ii — the sixth `ScreenCapture` backend.
//!
//! The daemon spawns [`super::helper`] in streaming mode, reads the handshake
//! line, then reads framed pixels off the child's stdout for as long as the
//! capture lasts.
//!
//! ⚠️ **stdout is binary after the handshake; diagnostics go to stderr.** The
//! same rule the SSH subsystem documents for `sftp-server` — a stray `println!`
//! in the child does not produce a stray log line here, it corrupts a frame and
//! desynchronises the stream. The wire format's magic exists so that failure is
//! loud at the next boundary rather than silent.

use anyhow::{Result, anyhow};

fn now_us() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_micros() as u64)
        .unwrap_or(0)
}

use super::wire::{FrameHeader, HEADER_LEN};
use crate::capture::{Damage, Frame, PixelFormat, ScreenCapture};

/// A portal capture session: a child in the user's session, and its frames.
pub struct PortalCapture {
    child: std::process::Child,
    /// Depth 1 and lossy: the pump wants the newest frame, and a queue of
    /// stale ones is latency with extra steps.
    rx: std::sync::mpsc::Receiver<Frame>,
    width: u32,
    height: u32,
    /// P4 — the generation token of the input route this capture registered,
    /// present while it owns the process's injected input. `Drop` unregisters
    /// with it, so a stale drop can never tear down a successor's route.
    input_route_generation: Option<u64>,
    /// FR-85 P1d — the compositor draws the pointer into the frames.
    cursor_embedded: bool,
    /// FR-93 P2 — frames from mutter's own ScreenCast, not the portal: the
    /// arm the controller is told about.
    mutter: bool,
    /// FR-93 P5f — whether this user's display session is the one on its
    /// seat (a user switch, the login screen), as [`watch_session`] last read
    /// it. `None` where nothing watches: a root daemon, or
    /// `ROOMLERD_SESSION_WATCH=0`.
    watch: Option<std::sync::Arc<SessionWatch>>,
    /// When the last frame arrived: proof the compositor draws this session,
    /// newer than the watch's read on the way back (see [`away_now`]).
    last_frame: Option<std::time::Instant>,
}

/// What one portal session is opened with. [`PortalOpen::from_env`] is the
/// configured answer. FR-93 P2's automatic arms build their own, because the
/// keys they act on are unset by definition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortalOpen {
    /// Frames from `org.gnome.Mutter.ScreenCast`, which asks nobody.
    pub mutter: bool,
    /// Input over the same session's RemoteDesktop.
    pub input: bool,
    /// One window rather than the desktop: a picker, so attended.
    pub window: bool,
}

impl PortalOpen {
    pub fn from_env() -> Self {
        let mutter = tunnel_core::env::flag("MUTTER_CAPTURE", false);
        let input = tunnel_core::env::flag("PORTAL_INPUT", false)
            // FR-93 P4 — on the mutter arm, input rides mutter's RemoteDesktop,
            // and `mutter_input = false` keeps it view-only there too.
            && (!mutter || super::mutter::input_enabled());
        Self {
            // P4 — input rides the same portal session ONLY when the operator
            // opts in (`ROOMLERD_PORTAL_INPUT=1`). Default OFF, deliberately: a
            // `WithInput` session uses a SEPARATE consent grant and restore
            // token from capture-only, so defaulting it on would make every
            // portal capture — even on a host that already granted+persisted
            // capture — demand a FRESH see+touch dialog, and block or fall
            // through if it is not answered. That regresses capture on hosts
            // where capture-only works, to buy an input path that has not yet
            // been field-proven to land. Off by default keeps capture
            // byte-for-byte P3c; a host that wants input turns it on.
            // ⚠️ This is the CONFIGURED arm's rule. The automatic portal (FR-93
            // P4b, `capture::auto_portal_input`) asks for remote control unless
            // `portal_input = false`: nothing was granted there before, so its
            // first dialog may as well ask for both.
            input,
            // FR-45 P5 — take frames from mutter's own ScreenCast API instead
            // of the portal. ⚠️⚠️ UNATTENDED: it shows no consent dialog.
            // Default OFF and loud when it engages, exactly like FR-36's DRM
            // backend, which is its real peer — NOT the portal, whose whole
            // point is that it asks.
            mutter,
            // FR-56 P4 — record one application window rather than the
            // desktop. ⚠️ Default OFF and it must stay that way: the portal
            // answers this by showing a WINDOW PICKER, so on an unattended
            // host the capture simply never starts. There is no way to name
            // the window from here — GNOME refuses `Introspect.GetWindows`
            // (measured), so mutter's `RecordWindow` has no id to take either.
            window: tunnel_core::env::flag("WINDOW_CAPTURE", false),
        }
    }
}

impl PortalCapture {
    /// Spawn the helper and wait for its first frame, as configured.
    ///
    /// Returns an error rather than an empty capturer when anything fails, so
    /// `open_default` can fall through to the rest of the cascade with a reason
    /// in the log.
    pub fn open(target_fps: u32) -> Result<Self> {
        Self::open_with(target_fps, PortalOpen::from_env())
    }

    /// [`Self::open`] with the session's options given, not read.
    pub fn open_with(target_fps: u32, opts: PortalOpen) -> Result<Self> {
        let PortalOpen {
            mutter: use_mutter,
            input: want_input,
            window: window_capture,
        } = opts;
        if use_mutter {
            tracing::warn!(
                "portal capture: using org.gnome.Mutter.ScreenCast DIRECTLY — this captures \
                 WITHOUT a consent dialog"
            );
        }
        if window_capture {
            tracing::info!(
                "portal capture: asking for ONE WINDOW (ROOMLERD_WINDOW_CAPTURE=1) — the portal \
                 will show a picker, so somebody has to be at the screen"
            );
        }
        let mut child =
            super::helper::spawn_streaming(target_fps, want_input, use_mutter, window_capture)?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| anyhow!("the portal helper has no stdout"))?;

        // 1. The handshake, then frames — on ONE thread that owns the reader.
        //    The handshake is read under a DEADLINE (via the channel below): a
        //    portal `Start` blocks until a human answers the consent dialog,
        //    and `PortalCapture::open` is called synchronously on a runtime
        //    worker inside the media pump, so an unanswered dialog would
        //    otherwise park that worker forever. A bounded wait fails the
        //    open instead, and the capture cascade falls through with a reason.
        let (hs_tx, hs_rx) = std::sync::mpsc::channel::<Result<super::helper::StreamStarted>>();
        let (tx, rx) = std::sync::mpsc::sync_channel(1);
        std::thread::spawn(move || {
            let mut reader = std::io::BufReader::new(stdout);
            let handshake = super::helper::read_stream_handshake(&mut reader);
            let ok = handshake.is_ok();
            if hs_tx.send(handshake).is_err() || !ok {
                // Either open() gave up (timed out) and went away, or the
                // handshake itself failed — nothing to stream either way.
                return;
            }
            // Frames. Bounded at 1: dropping a stale frame is the correct
            // behaviour for a live capture.
            loop {
                match read_frame(&mut reader) {
                    Ok(Some(f)) => {
                        let _ = tx.try_send(f);
                    }
                    Ok(None) => break, // clean EOF — the helper exited
                    Err(e) => {
                        tracing::warn!(error = %e, "portal capture: frame stream ended");
                        break;
                    }
                }
            }
        });

        let started = match hs_rx.recv_timeout(HANDSHAKE_DEADLINE) {
            Ok(Ok(s)) => s,
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                let _ = child.kill();
                let _ = child.wait();
                return Err(anyhow!(
                    "the portal helper did not start a stream within {}s — a consent dialog \
                     left unanswered, most likely (the portal is attended)",
                    HANDSHAKE_DEADLINE.as_secs()
                ));
            }
        };
        let (width, height) = (started.width, started.height);

        // 1b. P4 — the input wire: `InputMsg` JSON lines onto the helper's
        //     stdin, fed through a bounded channel so a wedged helper costs
        //     dropped input events, never a blocked arbiter thread.
        let mut input_route_generation = None;
        if started.input_ok {
            if let Some(stdin) = child.stdin.take() {
                let (in_tx, input_rx) =
                    std::sync::mpsc::sync_channel::<crate::input::InputMsg>(256);
                std::thread::spawn(move || {
                    use std::io::Write;
                    let mut w = std::io::BufWriter::new(stdin);
                    while let Ok(msg) = input_rx.recv() {
                        let Ok(line) = serde_json::to_string(&msg) else {
                            continue;
                        };
                        // Flushed per event: input is latency, not throughput.
                        if w.write_all(line.as_bytes()).is_err()
                            || w.write_all(b"\n").is_err()
                            || w.flush().is_err()
                        {
                            // The helper is gone; the route dies with the
                            // capture that registered it.
                            break;
                        }
                    }
                });
                // FR-93 P4 — a mutter helper's input rides mutter's own
                // RemoteDesktop session, the portal's rides the portal's.
                let kind = if use_mutter {
                    crate::input::reach::RouteKind::Mutter
                } else {
                    crate::input::reach::RouteKind::Portal
                };
                input_route_generation = Some(super::input_route::register(in_tx, kind));
                tracing::info!(
                    "portal capture: input routed through {}",
                    if use_mutter {
                        "mutter's RemoteDesktop session (FR-93 P4)"
                    } else {
                        "the portal RemoteDesktop session"
                    }
                );
            }
        } else if want_input {
            tracing::warn!(
                "portal capture: the helper reported no input — the session is VIEW-ONLY \
                 (no RemoteDesktop backend on this portal, or the devices were not granted)"
            );
        }

        // FR-93 P5f — a per-user install captures only its own user's session,
        // which the compositor stops drawing while another session holds the
        // seat. Watched, so the controller can be told why the picture stopped.
        let watch = watch_session();

        Ok(Self {
            child,
            rx,
            width,
            height,
            input_route_generation,
            cursor_embedded: started.cursor_embedded,
            mutter: use_mutter,
            watch,
            last_frame: None,
        })
    }

    pub fn width(&self) -> u32 {
        self.width
    }
    pub fn height(&self) -> u32 {
        self.height
    }
}

impl Drop for PortalCapture {
    /// ⚠️ Kill the helper explicitly. It holds a live portal session and a
    /// PipeWire stream; leaving it running would keep the compositor
    /// screencasting — and on GNOME that means the "screen is being shared"
    /// indicator stays up after the session ends, which is both a privacy
    /// surprise and a support call.
    fn drop(&mut self) {
        // The route first, so no event is claimed for a helper being killed.
        if let Some(generation) = self.input_route_generation.take() {
            super::input_route::unregister(generation);
        }
        if let Some(watch) = &self.watch {
            watch.stop.store(true, std::sync::atomic::Ordering::Relaxed);
        }
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// FR-93 P5f — how often the user's display session is asked whether it is
/// on its seat: a D-Bus property read, no process.
const SESSION_POLL: std::time::Duration = std::time::Duration::from_secs(1);

/// FR-93 P5f kill switch `ROOMLERD_SESSION_WATCH=0`: no watcher, and a
/// session switched away reads as it did before, its last frame kept alive.
fn session_watch_enabled() -> bool {
    tunnel_core::env::flag("SESSION_WATCH", true)
}

/// FR-93 P5f — a watcher of this user's display session, for a per-user
/// daemon: its read says "away" while logind says the session is not the
/// active one on its seat, and the thread ends when `stop` is set. `None` for
/// a root daemon, whose captures are not one user's, or with the kill switch.
fn watch_session() -> Option<std::sync::Arc<SessionWatch>> {
    use std::sync::atomic::Ordering;
    // SAFETY: geteuid has no preconditions and cannot fail.
    let uid = unsafe { libc::geteuid() };
    if uid == 0 || !session_watch_enabled() {
        return None;
    }
    let watch = std::sync::Arc::new(SessionWatch::new());
    let thread_watch = std::sync::Arc::clone(&watch);
    let spawned = std::thread::Builder::new()
        .name("session-watch".into())
        .spawn(move || {
            let Ok(conn) = zbus::blocking::Connection::system() else {
                return;
            };
            let mut was_away = false;
            while !thread_watch.stop.load(Ordering::Relaxed) {
                let began = std::time::Instant::now();
                let now_away = session_away(&seat_sessions(&conn, uid));
                if now_away != was_away {
                    tracing::info!(
                        away = now_away,
                        "capture: this user's session is {} its seat (FR-93 P5f)",
                        if now_away { "away from" } else { "back on" }
                    );
                    was_away = now_away;
                }
                thread_watch.record(now_away, began);
                std::thread::sleep(SESSION_POLL);
            }
        });
    spawned.ok().map(|_| watch)
}

/// FR-93 P5f — what the session watch last read, shared by its thread and
/// the capture, and the capture's word to stop it.
struct SessionWatch {
    /// The last read: [`SessionWatch::AWAY`] for "away", and below it when
    /// the read began, in µs since `base`. One word, so an answer is never
    /// read with another answer's time.
    read: std::sync::atomic::AtomicU64,
    base: std::time::Instant,
    stop: std::sync::atomic::AtomicBool,
}

impl SessionWatch {
    /// The top bit of [`SessionWatch::read`].
    const AWAY: u64 = 1 << 63;

    /// Nothing read yet: not away.
    fn new() -> Self {
        Self {
            read: std::sync::atomic::AtomicU64::new(0),
            base: std::time::Instant::now(),
            stop: std::sync::atomic::AtomicBool::new(false),
        }
    }

    /// A read's answer, with the time it began.
    fn record(&self, away: bool, began: std::time::Instant) {
        use std::sync::atomic::Ordering;
        let at = began.saturating_duration_since(self.base).as_micros() as u64 & !Self::AWAY;
        let flag = if away { Self::AWAY } else { 0 };
        self.read.store(at | flag, Ordering::Relaxed);
    }

    /// The last read: away or not, and when it began.
    fn last(&self) -> (bool, std::time::Instant) {
        use std::sync::atomic::Ordering;
        let read = self.read.load(Ordering::Relaxed);
        (
            read & Self::AWAY != 0,
            self.base + std::time::Duration::from_micros(read & !Self::AWAY),
        )
    }
}

/// FR-93 P5f — the newer evidence wins. logind's "away" counts only when its
/// read began after the last frame: a frame proves the compositor draws this
/// session, and on the way back the frames come before the next read. Without
/// this, a still desktop's first empty tick after the return told the
/// controller "away" again, once, after its picture had come back.
fn away_now(
    away: bool,
    read_began: std::time::Instant,
    last_frame: Option<std::time::Instant>,
) -> bool {
    away && last_frame.is_none_or(|frame| read_began > frame)
}

/// FR-93 P5f — away when this user has a graphical session on a seat and none
/// of them is the active one there. No graphical seat session (logged out,
/// or logind could not be asked) is not "away": the capture goes on as before,
/// and the session's own end is another path's to report.
fn session_away(sessions: &[SeatSession]) -> bool {
    let mut graphical = sessions.iter().filter(|s| s.graphical).peekable();
    graphical.peek().is_some() && graphical.all(|s| !s.active)
}

/// One of this user's sessions on a seat, as logind reports it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SeatSession {
    /// `Type` is `wayland` or `x11`.
    graphical: bool,
    /// `Active`: the session is the one its seat shows.
    active: bool,
}

/// FR-93 P5f — this user's sessions on a seat (`ListSessions`, then each
/// one's `Type` and `Active`). Empty when logind cannot be asked.
fn seat_sessions(conn: &zbus::blocking::Connection, uid: u32) -> Vec<SeatSession> {
    use zbus::blocking::Proxy;
    use zbus::zvariant::OwnedObjectPath;
    const LOGIND: &str = "org.freedesktop.login1";
    let Ok(manager) = Proxy::new(
        conn,
        LOGIND,
        "/org/freedesktop/login1",
        "org.freedesktop.login1.Manager",
    ) else {
        return Vec::new();
    };
    let Ok(all) = manager
        .call::<_, _, Vec<(String, u32, String, String, OwnedObjectPath)>>("ListSessions", &())
    else {
        return Vec::new();
    };
    all.iter()
        .filter(|(_id, owner, _name, seat, _path)| *owner == uid && !seat.is_empty())
        .filter_map(|(_id, _owner, _name, _seat, path)| {
            let session = Proxy::new(conn, LOGIND, path, "org.freedesktop.login1.Session").ok()?;
            let kind = session.get_property::<String>("Type").ok()?;
            let active = session.get_property::<bool>("Active").ok()?;
            Some(SeatSession {
                graphical: kind == "wayland" || kind == "x11",
                active,
            })
        })
        .collect()
}

#[cfg(test)]
mod session_away_tests {
    use super::{SeatSession, SessionWatch, away_now, session_away};
    use std::time::{Duration, Instant};

    const fn s(graphical: bool, active: bool) -> SeatSession {
        SeatSession { graphical, active }
    }

    /// P5f — away only when this user's graphical seat session exists and is
    /// not the one on screen; a user with none is not away (logged out, or
    /// logind silent), and a tty login on the seat does not count.
    #[test]
    fn away_means_a_graphical_session_that_is_not_on_screen() {
        assert!(!session_away(&[]), "no seat session: not away");
        assert!(!session_away(&[s(true, true)]), "on screen");
        assert!(
            session_away(&[s(true, false)]),
            "a user switch, the greeter"
        );
        assert!(
            !session_away(&[s(false, false)]),
            "a tty only: no picture to lose"
        );
        assert!(
            !session_away(&[s(true, false), s(true, true)]),
            "one of them on screen"
        );
        assert!(
            session_away(&[s(false, true), s(true, false)]),
            "the tty is the active one, the desktop is not"
        );
    }

    /// P5f — the newer evidence wins: a frame after the read that said "away"
    /// means the session came back before the watch read it again, so only a
    /// read newer than the last frame counts.
    #[test]
    fn a_frame_newer_than_the_read_means_the_session_is_back() {
        let read = Instant::now();
        let later = read + Duration::from_millis(400);
        assert!(away_now(true, read, None), "away, and no frame yet");
        assert!(
            away_now(true, later, Some(read)),
            "a read newer than the frame"
        );
        assert!(
            !away_now(true, read, Some(later)),
            "a frame after the read: back"
        );
        assert!(!away_now(false, later, Some(read)), "not away");
    }

    /// P5f — the watch's one word keeps an answer with its own time.
    #[test]
    fn the_watch_keeps_each_answer_with_its_time() {
        let watch = SessionWatch::new();
        assert!(!watch.last().0, "nothing read yet: not away");
        let began = watch.base + Duration::from_millis(1500);
        watch.record(true, began);
        assert_eq!(watch.last(), (true, began));
        let back = began + Duration::from_secs(1);
        watch.record(false, back);
        assert_eq!(watch.last(), (false, back));
    }
}

/// Read one framed frame. `Ok(None)` is a clean end of stream.
fn read_frame(r: &mut impl std::io::Read) -> Result<Option<Frame>> {
    let mut head = [0u8; HEADER_LEN];
    match r.read_exact(&mut head) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let h = FrameHeader::decode(&head).map_err(|e| anyhow!("{e}"))?;
    let mut data = vec![0u8; h.len as usize];
    r.read_exact(&mut data)?;

    Ok(Some(Frame {
        width: h.width,
        height: h.height,
        stride: h.stride,
        pixel_format: pixel_format_of(h.video_format)?,
        data,
        monotonic_us: now_us(),
        monitor: 0,
        // ⚠️ The portal reports no damage, so every frame is "assume
        // everything changed". `Unknown` is the pre-FR-29 contract and the
        // honest answer — claiming `Tracked(&[])` would tell the pump nothing
        // changed and freeze the picture.
        damage: Damage::Unknown,
        // Never scaled here: the compositor delivers what it negotiated.
        source: None,
    }))
}

/// Map `enum spa_video_format` onto what the encode path understands.
///
/// ⚠️ Refuses anything else rather than guessing. Our `EnumFormat` only offers
/// these four, so a fifth means the compositor ignored the offer — and
/// mislabelling a pixel order produces a picture with swapped colour channels,
/// which reads as a codec bug.
fn pixel_format_of(video_format: u32) -> Result<PixelFormat> {
    use super::pod::ty;
    match video_format {
        // BGRx and BGRA are the same byte order to a consumer that ignores
        // alpha, which is what the encode path does.
        ty::VIDEO_FORMAT_BGRX | ty::VIDEO_FORMAT_BGRA => Ok(PixelFormat::Bgra),
        other => Err(anyhow!(
            "the compositor chose spa_video_format {other}, which was not in our offer"
        )),
    }
}

#[async_trait::async_trait]
impl ScreenCapture for PortalCapture {
    async fn next_frame(&mut self) -> Result<Option<Frame>> {
        // The helper paces to the negotiated rate, so this waits on it rather
        // than sleeping on a timer of its own — two pacers would beat against
        // each other.
        let rx = &self.rx;
        match tokio::task::block_in_place(|| rx.recv_timeout(FRAME_WAIT)) {
            Ok(f) => {
                // FR-93 P5f — proof the compositor draws this session.
                self.last_frame = Some(std::time::Instant::now());
                Ok(Some(f))
            }
            // No frame inside the window is not an error: a still screen
            // legitimately produces nothing, and `Ok(None)` is the pump's
            // "nothing this tick".
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Ok(None),
            // FR-93 P6c — why the helper ended is in its exit status, which
            // follows its stdout closing within moments.
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                let child = &mut self.child;
                let code = tokio::task::block_in_place(|| reap(child, HELPER_EXIT_WAIT))
                    .and_then(|s| s.code());
                Err(helper_ended(code, screen_stop_enabled()))
            }
        }
    }

    fn monitor_count(&self) -> u8 {
        // The portal hands us exactly the one source the user picked.
        1
    }

    /// FR-85 P1d. The helper asks for an embedded cursor wherever the portal
    /// offers one; a portal that offers only hidden (or metadata) leaves the
    /// recording without a pointer, and its sidecar says so.
    fn recorded_pointer(&mut self) -> crate::capture::pointer::RecordedPointer {
        if self.cursor_embedded {
            crate::capture::pointer::RecordedPointer::InFrame
        } else {
            crate::capture::pointer::RecordedPointer::Absent
        }
    }

    fn arm(&self) -> Option<crate::capture::CaptureArm> {
        Some(if self.mutter {
            crate::capture::CaptureArm::Mutter
        } else {
            crate::capture::CaptureArm::Portal
        })
    }

    /// FR-119 P2b — the arm's own name. The pace is the helper's, negotiated
    /// at the open, so `set_target_fps` keeps the default: a trial above it
    /// fails on what the helper delivers.
    fn backend(&self) -> &'static str {
        if self.mutter { "mutter" } else { "portal" }
    }

    /// FR-93 P5f — this user's session is away from its seat: the pumps tell
    /// the controller, and keep no keepalive while it lasts.
    fn waits_for(&self) -> Option<crate::capture::WaitFor> {
        let (away, read_began) = self.watch.as_ref()?.last();
        away_now(away, read_began, self.last_frame).then_some(crate::capture::WaitFor::SessionAway)
    }
}

/// FR-93 P6c kill switch `ROOMLERD_SCREEN_STOP=0`: a share stopped at the
/// screen is reopened, as before P6c.
fn screen_stop_enabled() -> bool {
    tunnel_core::env::flag("SCREEN_STOP", true)
}

/// How long a pump waits for a helper whose stdout closed to exit.
const HELPER_EXIT_WAIT: std::time::Duration = std::time::Duration::from_secs(1);

/// FR-93 P6c — the helper's exit status once its stdout has closed: the pipe
/// closes as the process exits, so the status follows within moments. Bounded,
/// so a helper that closed its stdout and lingers cannot hold the pump.
fn reap(
    child: &mut std::process::Child,
    within: std::time::Duration,
) -> Option<std::process::ExitStatus> {
    let until = std::time::Instant::now() + within;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) if std::time::Instant::now() < until => {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            _ => return None,
        }
    }
}

/// FR-93 P6c — what a pump reads when the helper stopped. The person's Stop
/// is typed, and the pump ends the session; any other end is the error it
/// always was, and the pump reopens. The status goes in for the journal.
fn helper_ended(code: Option<i32>, honour_stop: bool) -> anyhow::Error {
    match code {
        Some(c) if c == super::helper::EXIT_STOPPED_AT_SCREEN && honour_stop => {
            anyhow::Error::new(crate::capture::StoppedAtScreen)
        }
        Some(c) => anyhow!("the portal helper stopped producing frames (exit status {c})"),
        None => anyhow!("the portal helper stopped producing frames"),
    }
}

/// How long a single `next_frame` waits before reporting "nothing this tick".
/// Long enough not to spin on a still screen, short enough that the pump stays
/// responsive to a resize or a teardown.
const FRAME_WAIT: std::time::Duration = std::time::Duration::from_millis(250);

/// How long `open` waits for the helper's stream handshake before giving up.
/// Generous, because the very first session (or a fresh input grant) blocks on
/// a human answering the portal's consent dialog — but bounded, because an
/// unanswered dialog must not park a media-pump worker forever. Restored,
/// already-granted sessions return in well under a second.
pub(super) const HANDSHAKE_DEADLINE: std::time::Duration = std::time::Duration::from_secs(120);

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn framed(h: FrameHeader, fill: u8) -> Vec<u8> {
        let mut v = Vec::new();
        v.write_all(&h.encode()).unwrap();
        v.write_all(&vec![fill; h.len as usize]).unwrap();
        v
    }

    fn hdr(len: u32) -> FrameHeader {
        FrameHeader {
            width: 4,
            height: 2,
            stride: 16,
            video_format: 8,
            len,
        }
    }

    /// Two frames back to back must both come out — the reader has to consume
    /// exactly the declared payload or it lands mid-pixels on the next header.
    #[test]
    fn frames_are_read_back_to_back() {
        let mut buf = framed(hdr(32), 0xAB);
        buf.extend(framed(hdr(32), 0xCD));
        let mut cur = std::io::Cursor::new(buf);

        let a = read_frame(&mut cur).unwrap().unwrap();
        assert_eq!((a.width, a.height, a.stride), (4, 2, 16));
        assert!(a.data.iter().all(|b| *b == 0xAB));

        let b = read_frame(&mut cur).unwrap().unwrap();
        assert!(b.data.iter().all(|b| *b == 0xCD));

        assert!(
            read_frame(&mut cur).unwrap().is_none(),
            "clean EOF expected"
        );
    }

    /// A truncated payload is an error, not a short frame handed to the
    /// encoder — half a frame encodes as garbage rather than failing.
    #[test]
    fn a_truncated_payload_is_an_error() {
        let mut buf = framed(hdr(32), 1);
        buf.truncate(HEADER_LEN + 10);
        let mut cur = std::io::Cursor::new(buf);
        assert!(read_frame(&mut cur).is_err());
    }

    /// Only the formats we offered are accepted; anything else would mean
    /// guessing a byte order, and a wrong guess looks like a codec bug.
    #[test]
    fn an_unoffered_pixel_format_is_refused() {
        use super::super::pod::ty;
        assert!(pixel_format_of(ty::VIDEO_FORMAT_BGRX).is_ok());
        assert!(pixel_format_of(ty::VIDEO_FORMAT_BGRA).is_ok());
        let e = pixel_format_of(99).unwrap_err().to_string();
        assert!(e.contains("not in our offer"), "{e}");
    }

    /// FR-93 P6c — only the person's Stop is typed, so only it ends the
    /// session, and `ROOMLERD_SCREEN_STOP=0` makes it the plain error that
    /// reopens. Every other end keeps the error it was, with its status.
    #[test]
    fn only_the_stop_at_the_screen_is_typed_and_the_switch_turns_it_off() {
        let stop = super::super::helper::EXIT_STOPPED_AT_SCREEN;
        let typed = |e: anyhow::Error| crate::capture::stopped_at_screen(&e);
        assert!(typed(helper_ended(Some(stop), true)));
        assert!(!typed(helper_ended(Some(stop), false)));
        for code in [Some(0), Some(1), Some(3), Some(4), None] {
            assert!(!typed(helper_ended(code, true)), "{code:?}");
        }
        let e = helper_ended(Some(3), true).to_string();
        assert!(e.contains("exit status 3"), "{e}");
    }

    /// P6c — a real child's status is read once it has exited, and a child
    /// still running is not waited on past the bound.
    #[test]
    fn a_helper_s_status_is_reaped_within_the_bound() {
        let mut done = std::process::Command::new("sh")
            .args(["-c", "exit 5"])
            .spawn()
            .unwrap();
        let status = reap(&mut done, std::time::Duration::from_secs(5));
        assert_eq!(status.and_then(|s| s.code()), Some(5));

        let mut running = std::process::Command::new("sleep")
            .arg("30")
            .spawn()
            .unwrap();
        let t0 = std::time::Instant::now();
        assert!(reap(&mut running, std::time::Duration::from_millis(100)).is_none());
        assert!(t0.elapsed() < std::time::Duration::from_secs(5));
        let _ = running.kill();
        let _ = running.wait();
    }
}
