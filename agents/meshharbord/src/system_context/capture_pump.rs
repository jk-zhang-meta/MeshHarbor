// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! M3 A1 SYSTEM-context capture pump.
//!
//! Bridges the M3 A1 backends ([`DxgiDupBackend`] + [`GdiBackend`])
//! behind the existing [`crate::capture::ScreenCapture`] trait, so
//! `peer.rs::media_pump` consumes one uniform interface regardless of
//! which worker context is running. The user-context worker keeps
//! using the WGC / scrap backends; the SYSTEM-context worker (chosen
//! at startup via [`super::worker_role::probe_self`]) uses this.
//!
//! ## Lifecycle
//!
//! 1. [`SystemContextCapture::primary`] spawns a dedicated OS thread
//!    (because both [`DxgiDupBackend`] and [`GdiBackend`] are `!Send`
//!    on Windows — D3D11 / GDI handles have thread affinity).
//! 2. The thread first calls [`super::desktop_rebind::attach_to_winsta0`]
//!    (idempotent — required so `OpenDesktopW` for `Default` /
//!    `Winlogon` is reachable from the SCM-spawned worker).
//! 3. Then [`super::desktop_rebind::try_change_desktop`] binds the
//!    thread to whichever desktop currently receives input — usually
//!    `Default` at startup, may flip to `Winlogon` after a `Win+L`.
//! 4. Builds a [`DxgiDupBackend`] against the primary monitor.
//! 5. Loops on capture commands from the async side (via
//!    `oneshot::Sender<CaptureReply>`) until the channel is dropped.
//!
//! ## BackendBail routing (matches RustDesk's
//! `video_service.rs:851-856` trip-wire convention):
//!
//! | Bail variant | Routed to |
//! |---|---|
//! | `Transient` | `Ok(None)` — no frame this tick (idle-keepalive will fire upstream) |
//! | `DesktopMismatch` | `try_change_desktop` rebind, then `Ok(None)` |
//! | `AccessLost` | `DxgiDupBackend::reset()`, then `Ok(None)` |
//! | `SessionGone` | `Err(...)` — terminal, supervisor tears down |
//! | `HardError` (×3 consecutive) | swap to GDI fallback |
//! | `HardError` (1-2 consecutive) | log + `Ok(None)` |
//!
//! After GDI takes over, every successful GDI frame *also* re-tries
//! DXGI on the next tick — we want to climb back to the GPU path as
//! soon as it recovers (driver reset, hybrid GPU re-enumeration). On
//! GDI-also-failing, return `Err(...)` and let `media_pump` rebuild
//! the entire pump.

#![cfg(all(feature = "system-context", target_os = "windows"))]

use anyhow::{Result, anyhow};
use std::sync::mpsc as std_mpsc;
use std::thread;
use std::time::{Duration, Instant};
use tokio::sync::oneshot;

use crate::capture::{DownscalePolicy, Frame, PixelFormat, ScreenCapture};

use super::desktop_rebind;
#[cfg(all(feature = "mf-encoder", feature = "scrap-capture"))]
use super::dxgi_direct::DxgiDirectBackend;
#[cfg(feature = "scrap-capture")]
use super::dxgi_dup::{BackendBail, DxgiCapture, DxgiDupBackend, DxgiFrame};
use super::gdi_backend::{GdiBackend, GdiFrame};

/// After this many consecutive `BackendBail::HardError` returns from
/// DXGI we drop the backend and switch to GDI. RustDesk uses 3 (see
/// `video_service.rs:851-856`); we mirror that — gives one frame of
/// "is this a real failure?" hysteresis without leaving the operator
/// staring at empty frames for long.
#[cfg_attr(not(feature = "scrap-capture"), allow(dead_code))]
const HARD_ERROR_FALLBACK_THRESHOLD: u32 = 3;

/// After this many consecutive `BackendBail::AccessLost` returns we
/// also switch to GDI. AccessLost during a Win+L cycle persists for
/// 3-5 seconds while the OS rebuilds the display compositor; spinning
/// `b.reset()` 20 times per second over that window is ~30-50ms of
/// GPU work per cycle, which starves the encoder + send threads and
/// produces visible blocky motion (field repro the field-test host rc.9 lock/unlock
/// cycle: ~80 recreate attempts in 4 s, mouse motion not smooth).
/// 8 consecutive AccessLost ≈ 400 ms — enough to be sure it's not a
/// single transient blip but fast enough that the operator doesn't
/// stare at black frames for long.
#[cfg_attr(not(feature = "scrap-capture"), allow(dead_code))]
const ACCESS_LOST_FALLBACK_THRESHOLD: u32 = 8;

/// FR-34 — how long a backend may run WITHOUT delivering a single frame before
/// we treat it as STUCK rather than idle. A DXGI Desktop Duplication bound
/// during a lock→unlock desktop transition returns `WAIT_TIMEOUT`
/// (`BackendBail::Transient`) forever — bound to a desktop that will never
/// change — so `consecutive_empty` climbs without bound and the controller
/// stays black (field CORPLAP-1 2026-08-29: 200k empty / 0 delivered / 13 s
/// black, recovered only by a reconnect). A working session that merely goes
/// idle has ALREADY delivered a frame and is exempt via `delivered_since_build`;
/// this only bounds the never-delivered case. 2 s: well past a healthy DXGI
/// first frame (<1 s), far under the 13 s the operator sat black.
const STUCK_CAPTURE_RECOVERY_AFTER: Duration = Duration::from_secs(2);

/// FR-34 P2 (first-frame guarantee). P1's stuck-recovery already prevents a
/// PERMANENT black on a genuinely static screen — but only after
/// [`STUCK_CAPTURE_RECOVERY_AFTER`] (2 s), because a static desktop makes DXGI
/// `AcquireNextFrame` WAIT_TIMEOUT (deliver nothing) with no way to tell it
/// apart from a stuck duplication until the window elapses. This shorter window
/// primes ONE GDI BitBlt frame — which always grabs the current screen — so the
/// controller sees the desktop within ~300 ms of connect instead of ~2 s.
/// Deliberately does NOT swap the backend or set `delivered_since_build`: DXGI
/// keeps running and takes over at full quality the instant it delivers a real
/// frame (so a merely-slow-first-frame DXGI is never abandoned), and a
/// truly-STUCK DXGI is still caught by the 2 s stuck-recovery below. One-shot
/// per session via `first_frame_primed`.
const FIRST_FRAME_GDI_AFTER: Duration = Duration::from_millis(300);

/// FR-34 kill switch. `ROOMLERD_STUCK_CAPTURE_RECOVERY=0` restores the
/// pre-FR-34 behaviour (a stuck duplication stays black until a reconnect).
#[cfg_attr(not(feature = "scrap-capture"), allow(dead_code))]
fn stuck_capture_recovery_enabled() -> bool {
    !matches!(
        std::env::var("ROOMLERD_STUCK_CAPTURE_RECOVERY").as_deref(),
        Ok("0") | Ok("false") | Ok("no")
    )
}

/// The FR-34 stuck-vs-idle decision, pure so it is unit-testable off-Windows.
/// STUCK = the current backend has delivered no frame since it was built AND
/// has run longer than [`STUCK_CAPTURE_RECOVERY_AFTER`]. A backend that has
/// ever delivered (`delivered_since_build`) is idle, never stuck — which is why
/// `consecutive_empty` alone cannot make this call (a long idle looks identical
/// to a stuck duplication by that counter).
#[cfg_attr(not(feature = "scrap-capture"), allow(dead_code))]
fn capture_is_stuck(delivered_since_build: bool, backend_age: Duration) -> bool {
    !delivered_since_build && backend_age >= STUCK_CAPTURE_RECOVERY_AFTER
}

/// FR-34 P2 — should this tick prime a one-shot GDI first frame? True when the
/// backend has delivered NO frame yet, we have not already primed one this
/// session, and the shorter [`FIRST_FRAME_GDI_AFTER`] window has elapsed. Pure so
/// it is unit-testable off-Windows. The full stuck window ([`capture_is_stuck`])
/// is strictly longer, so a screen that is merely slow to first-frame primes ONE
/// GDI frame here and is NOT declared stuck.
#[cfg_attr(not(feature = "scrap-capture"), allow(dead_code))]
fn first_frame_should_prime(
    delivered_since_build: bool,
    first_frame_primed: bool,
    backend_age: Duration,
) -> bool {
    !delivered_since_build && !first_frame_primed && backend_age >= FIRST_FRAME_GDI_AFTER
}

/// rc.108 — once we've fallen back to the slow GDI BitBlt path, retry DXGI
/// at most this often. The doc-comment has promised a DXGI re-climb since
/// M3 A1 but the GDI arm never actually did it (latent bug noted in the
/// hybrid-GPU memory) — so a transient Optimus AccessLost / driver reset
/// pinned the host on ~12 fps GDI forever. 5 s is long enough that a
/// rebuild storm (DXGI keeps failing → 3 frames lost → back to GDI) costs
/// negligible CPU, short enough that recovery is quick once DXGI is healthy.
#[cfg(feature = "scrap-capture")]
const DXGI_RECLIMB_INTERVAL: Duration = Duration::from_secs(5);

/// Active capture backend. Starts as DXGI; swaps to GDI on persistent
/// HardError; can climb back to DXGI when it recovers. The DXGI variant is
/// boxed behind [`DxgiCapture`] so it can hold either the adapter-bound
/// [`DxgiDirectBackend`] (preferred — correct on hybrid Optimus hosts) or
/// the `scrap` auto-adapter [`DxgiDupBackend`] (fallback) transparently.
#[cfg(feature = "scrap-capture")]
enum ActiveBackend {
    Dxgi(Box<dyn DxgiCapture>),
    Gdi(GdiBackend),
}

#[cfg(not(feature = "scrap-capture"))]
enum ActiveBackend {
    Gdi(GdiBackend),
}

type CaptureReply = Result<Option<Frame>>;

/// One capture request. Phase B — carries the pump's current effective
/// encode box per request (race-free vs a shared cell) so a GPU-capable
/// backend can scale BEFORE the CPU readback; `None` = deliver native.
struct CaptureCmd {
    reply: oneshot::Sender<CaptureReply>,
    output_cap: Option<(u32, u32)>,
}

/// Async-side handle. `cmd_tx` posts capture requests to the worker
/// thread; the worker fills the embedded oneshot.
pub struct SystemContextCapture {
    cmd_tx: std_mpsc::Sender<CaptureCmd>,
    width: u32,
    height: u32,
    /// Phase B — the pump's latest `set_output_cap`, attached to every
    /// subsequent request.
    output_cap: Option<(u32, u32)>,
}

impl SystemContextCapture {
    /// Spawn the worker thread + initialise DXGI (or GDI fallback).
    /// Surfaces init failures synchronously via a ready-ack channel —
    /// if both DXGI and GDI fail at startup the caller decides how to
    /// degrade (typically falls back to `NoopCapture`).
    pub fn primary(_target_fps: u32, _downscale: DownscalePolicy) -> Result<Self> {
        let (ready_tx, ready_rx) = std_mpsc::channel::<Result<(u32, u32)>>();
        let (cmd_tx, cmd_rx) = std_mpsc::channel::<CaptureCmd>();

        thread::Builder::new()
            .name("roomlerd-system-capture".into())
            .spawn(move || {
                worker_main(ready_tx, cmd_rx);
            })
            .map_err(|e| anyhow!("spawning system-context capture thread: {e}"))?;

        let (width, height) = ready_rx
            .recv()
            .map_err(|_| anyhow!("system-context capture worker never acked"))??;

        Ok(Self {
            cmd_tx,
            width,
            height,
            output_cap: None,
        })
    }

    pub fn width(&self) -> u32 {
        self.width
    }
    pub fn height(&self) -> u32 {
        self.height
    }
}

#[async_trait::async_trait]
impl ScreenCapture for SystemContextCapture {
    async fn next_frame(&mut self) -> Result<Option<Frame>> {
        let (tx, rx) = oneshot::channel::<CaptureReply>();
        self.cmd_tx
            .send(CaptureCmd {
                reply: tx,
                output_cap: self.output_cap,
            })
            .map_err(|_| anyhow!("system-context capture worker thread is gone"))?;
        match rx.await {
            Ok(reply) => reply,
            Err(_) => Err(anyhow!(
                "system-context capture worker dropped reply oneshot"
            )),
        }
    }

    fn set_output_cap(&mut self, target: Option<(u32, u32)>) {
        self.output_cap = target;
    }

    /// FR-119 P2b — nothing to move: this backend has no pacer of its own and
    /// delivers at the display's rate (the open ignores its target too).
    fn set_target_fps(&mut self, _fps: u32) {}

    fn backend(&self) -> &'static str {
        "system-context"
    }

    fn monitor_count(&self) -> u8 {
        // M3 A1 captures the primary monitor only — see plan §4.
        // Multi-monitor capture stays in the user-context worker
        // (WGC has the dirty-rect API we need for that).
        1
    }
}

/// Worker thread main. Owns the `!Send` capture backend; receives
/// oneshot-wrapped capture commands from the async side.
fn worker_main(
    ready_tx: std_mpsc::Sender<Result<(u32, u32)>>,
    cmd_rx: std_mpsc::Receiver<CaptureCmd>,
) {
    // 1. Bootstrap window-station attachment. Skipped under user-mode
    //    test runs (already on WinSta0); idempotent on the real
    //    SYSTEM-context worker. Warn but don't fail — the SCM-service
    //    container has WinSta0 on its DACL by default for LocalSystem;
    //    the only environment that fails this is a stripped-down CI
    //    runner where we couldn't reach a real desktop anyway.
    if let Err(e) = desktop_rebind::attach_to_winsta0() {
        tracing::warn!(%e, "attach_to_winsta0 failed at worker startup — capture may not see Default/Winlogon desktops");
    }

    // 2. Bind to the current input desktop. On a logged-in user this
    //    is `Default`; on a freshly-locked machine it flips to
    //    `Winlogon`. Non-fatal at startup — the `try_change_desktop`
    //    call in the per-frame error path will retry on the first
    //    `DesktopMismatch`.
    match desktop_rebind::try_change_desktop() {
        Ok(desktop_rebind::DesktopChange::Unchanged) => {
            tracing::info!("system-context capture: thread already on input desktop");
        }
        Ok(desktop_rebind::DesktopChange::Switched(name)) => {
            tracing::info!(%name, "system-context capture: rebound to input desktop");
        }
        Err(e) => {
            tracing::warn!(%e, "try_change_desktop at startup — non-fatal, will retry on first DesktopMismatch");
        }
    }

    // rc.105 Phase 0 — log the DXGI adapter/output layout BEFORE picking
    // a backend, so a single rc:logs-fetch shows which adapter owns the
    // primary output and whether a render-only dGPU exposes zero outputs
    // (the Optimus signature behind the GDI-fallback / ~85ms-capture bug
    // on hybrid hosts like WINHOST-B). Best-effort; never blocks capture.
    #[cfg(feature = "mf-encoder")]
    super::dxgi_util::log_adapters_and_outputs();

    // 3. Build the primary backend. Prefer DXGI; fall back to GDI if
    //    DXGI fails to initialise (no GPU, driver missing, etc.).
    let mut backend = match build_initial_backend() {
        Ok(b) => b,
        Err(e) => {
            let _ = ready_tx.send(Err(e));
            return;
        }
    };

    let dims = backend_dimensions(&backend);
    if ready_tx.send(Ok(dims)).is_err() {
        // Caller dropped the ready channel — async side already gave
        // up. Nothing to do but exit.
        return;
    }

    let start = Instant::now();
    let mut consecutive_hard: u32 = 0;
    let mut consecutive_access_lost: u32 = 0;
    let mut consecutive_empty: u64 = 0;
    // FR-34 — has the CURRENT backend delivered a frame yet, and when was it
    // built. Reset together on every backend (re)build so a re-climbed DXGI
    // that comes up stuck is caught too. This pair distinguishes a stuck
    // duplication (never delivered) from a working session gone idle
    // (delivered, now Transient) — indistinguishable from `consecutive_empty`.
    let mut backend_built_at = Instant::now();
    let mut delivered_since_build = false;
    // FR-34 P2 — one-shot: has this SESSION primed a first frame via the
    // GDI backstop yet? Session-scoped (worker_main runs per SystemContextCapture,
    // i.e. per capture session), NOT reset on backend rebuild — the fast-first-frame
    // guarantee is only meaningful at connect, and a re-climbed backend's stuck
    // case is already the 2 s `capture_is_stuck` path.
    let mut first_frame_primed = false;
    // rc.108 — last time we attempted to climb back from a GDI fallback to
    // DXGI. Init to now() so the first re-climb attempt waits one full
    // interval (don't fight a just-failed DXGI startup). Only consulted on
    // the GDI path; harmlessly carried otherwise.
    let mut last_dxgi_reclimb = Instant::now();

    // rc.91 — worker-side capture timing. The pump-side heartbeat's
    // `avg_capture_ms` measures the WHOLE next_frame() round-trip
    // (mpsc command → this thread → scrap frame() → oneshot reply →
    // tokio reschedule). Field data (WINHOST-E, 2026-05-30) showed ~45ms
    // there under motion — far too slow for a ~3-5ms DXGI acquire+copy,
    // so the suspicion is the per-frame thread handoff dominates. This
    // accumulator times JUST the `capture_one_blocking` call (scrap
    // frame() + handling) on THIS thread; the diff between the
    // worker-side avg logged here and the pump-side `avg_capture_ms`
    // attributes the round-trip overhead. P8a follow-up: TIME-gated
    // (≥30 s between logs), not call-count-gated — pointer-only frames
    // now return Transient, so empty polls dominate the call rate
    // (~250-500/s) and the old every-150-calls gate flooded the log at
    // ~1.7 lines/s (field winhost-b, rc.428 rollout evening).
    let mut worker_capture_us: u64 = 0;
    let mut worker_capture_calls: u64 = 0;
    let mut worker_timing_logged_at = Instant::now();
    const WORKER_TIMING_LOG_EVERY: Duration = Duration::from_secs(30);

    while let Ok(cmd) = cmd_rx.recv() {
        let res_tx = cmd.reply;
        let cap_start = Instant::now();
        let reply = capture_one_blocking(
            &mut backend,
            &mut consecutive_hard,
            &mut consecutive_access_lost,
            &mut consecutive_empty,
            &mut last_dxgi_reclimb,
            &mut backend_built_at,
            &mut delivered_since_build,
            &mut first_frame_primed,
            start,
            cmd.output_cap,
        );
        worker_capture_us += cap_start.elapsed().as_micros() as u64;
        worker_capture_calls += 1;
        if worker_capture_calls >= 150
            && worker_timing_logged_at.elapsed() >= WORKER_TIMING_LOG_EVERY
        {
            let avg_ms = (worker_capture_us / worker_capture_calls) as f64 / 1000.0;
            tracing::info!(
                worker_avg_capture_ms = avg_ms,
                calls = worker_capture_calls,
                backend = backend_name(&backend),
                "system-context capture: worker-side scrap frame() timing (compare to pump heartbeat avg_capture_ms — the diff is the per-frame async round-trip)"
            );
            worker_capture_us = 0;
            worker_capture_calls = 0;
            worker_timing_logged_at = Instant::now();
        }
        // Best-effort send; if the async side dropped its rx the next
        // recv() above will error out and we exit cleanly.
        let _ = res_tx.send(reply);
    }
    tracing::info!("system-context capture worker thread exiting (cmd channel closed)");
}

#[cfg(feature = "scrap-capture")]
fn build_initial_backend() -> Result<ActiveBackend> {
    // Startup uses the retry-with-rebind builder so a transient E_ACCESSDENIED
    // (secure desktop up / session transition at the instant we build) doesn't
    // wrongly concede the fast DXGI path to GDI. The GDI re-climb path keeps
    // using the single-attempt `try_build_dxgi` (it must not block the
    // frame-serving thread).
    if let Some(b) = build_dxgi_with_retry() {
        return Ok(ActiveBackend::Dxgi(b));
    }
    tracing::warn!(
        "system-context capture: all DXGI backends failed at startup — falling back to GDI BitBlt"
    );
    let gdi = GdiBackend::primary()
        .map_err(|e| anyhow!("DXGI + GDI both failed to initialise at startup: gdi={e}"))?;
    Ok(ActiveBackend::Gdi(gdi))
}

/// rc.110 — bounded init retry for a recoverable `DesktopMismatch`
/// (E_ACCESSDENIED) at DXGI build. A denied duplication at startup is almost
/// always a desktop/session-transition RACE — secure desktop (UAC/lock) up at
/// the instant we build, a just-completed logon, or a fast-user-switch — not a
/// permanent capability gap. We rebind + back off + retry a handful of times
/// before conceding the fast DXGI path to the slow GDI fallback. 8 × 120 ms
/// caps the worst-case startup stall at ~1 s, after which a genuinely-denied
/// host still reaches GDI (and the 5 s re-climb keeps trying DXGI thereafter).
#[cfg(feature = "scrap-capture")]
const DXGI_INIT_MAX_ATTEMPTS: u32 = 8;
#[cfg(feature = "scrap-capture")]
const DXGI_INIT_RETRY_BACKOFF: Duration = Duration::from_millis(120);

/// One DXGI build attempt: rebind the worker thread to the CURRENT input
/// desktop, then try the adapter-bound direct backend (rc.108 hybrid-GPU fix),
/// then the `scrap` auto-adapter backend. Returns the TYPED [`BackendBail`] on
/// failure so the caller can tell a recoverable `DesktopMismatch`
/// (E_ACCESSDENIED — retry after rebind) from a terminal-for-DXGI `HardError`
/// (driver missing / unsupported — concede to GDI).
///
/// rc.109 — the rebind BEFORE the build matters: `DuplicateOutput` returns
/// E_ACCESSDENIED when the calling thread isn't on the desktop it's trying to
/// duplicate. `try_change_desktop` dedupes (SetThreadDesktop only on a real
/// change), so the steady-state cost is one OpenInputDesktop syscall. The
/// desktop name is logged so a PERSISTENT post-rebind E_ACCESSDENIED — the
/// thread IS on the right desktop but duplication is still denied (another
/// process holds it, or a session-0 nuance) — is distinguishable in the field.
///
/// On a hybrid Optimus host the direct backend binds Desktop Duplication to the
/// iGPU (which owns the display output) instead of the render-only dGPU `scrap`
/// picks — the difference between fast DXGI (~1-3 ms) and the slow GDI fallback
/// (~85 ms ⇒ 12 fps). On an Intel-only host both pick the same adapter, so the
/// scrap path is an exact-behaviour fallback if the direct backend hits an
/// unexpected init error.
#[cfg(feature = "scrap-capture")]
fn attempt_build_dxgi() -> Result<Box<dyn DxgiCapture>, BackendBail> {
    match desktop_rebind::try_change_desktop() {
        Ok(desktop_rebind::DesktopChange::Switched(name)) => {
            tracing::info!(%name, "attempt_build_dxgi: rebound input desktop before DXGI build");
        }
        Ok(desktop_rebind::DesktopChange::Unchanged) => {}
        Err(e) => {
            tracing::warn!(%e, "attempt_build_dxgi: desktop rebind failed before DXGI build");
        }
    }
    #[cfg(all(feature = "mf-encoder", feature = "scrap-capture"))]
    {
        match DxgiDirectBackend::primary() {
            Ok(b) => {
                tracing::info!("system-context capture: backend=DXGI (direct, adapter-bound)");
                return Ok(Box::new(b));
            }
            // E_ACCESSDENIED on the direct backend means the thread isn't on a
            // desktop it can duplicate yet — recoverable. Surface it straight to
            // the retry loop; the scrap backend would only hit the same denial
            // on this desktop, so there's nothing to gain from trying it now.
            Err(BackendBail::DesktopMismatch) => return Err(BackendBail::DesktopMismatch),
            Err(e) => {
                tracing::warn!(
                    ?e,
                    "direct-DXGI backend init failed after desktop rebind — trying scrap auto-adapter DXGI"
                );
            }
        }
    }
    match DxgiDupBackend::primary() {
        Ok(b) => {
            tracing::info!("system-context capture: backend=DXGI (scrap auto-adapter)");
            Ok(Box::new(b))
        }
        Err(e) => Err(e),
    }
}

/// Single-attempt DXGI build used by the GDI re-climb path (every
/// [`DXGI_RECLIMB_INTERVAL`]). Deliberately does NOT loop/back off: this runs
/// on the frame-serving worker thread, so blocking it for ~1 s would stall GDI
/// output — the 5 s re-climb cadence is itself the retry. Init failures (incl.
/// a recoverable `DesktopMismatch`) just stay on GDI until the next tick.
#[cfg(feature = "scrap-capture")]
fn try_build_dxgi() -> Option<Box<dyn DxgiCapture>> {
    match attempt_build_dxgi() {
        Ok(b) => Some(b),
        Err(BackendBail::DesktopMismatch) => {
            // Not logged at warn — the re-climb fires every 5 s and a desktop
            // race clears on its own; the GDI arm keeps serving frames meanwhile.
            tracing::debug!(
                "DXGI re-climb: E_ACCESSDENIED (desktop transition) — staying on GDI this tick"
            );
            None
        }
        Err(e) => {
            tracing::warn!(?e, "scrap DXGI backend init also failed");
            None
        }
    }
}

/// Resilient DXGI build used at worker STARTUP. Retries a recoverable
/// `DesktopMismatch` (E_ACCESSDENIED) with a rebind + backoff before conceding
/// to GDI — see [`DXGI_INIT_MAX_ATTEMPTS`]. Safe to block here: no frames are
/// being served yet (`SystemContextCapture::primary` is awaiting the ready-ack).
/// Returns `None` only when DXGI is genuinely unavailable (HardError) or still
/// denied after the full retry budget — the caller then drops to GDI.
#[cfg(feature = "scrap-capture")]
fn build_dxgi_with_retry() -> Option<Box<dyn DxgiCapture>> {
    for attempt in 1..=DXGI_INIT_MAX_ATTEMPTS {
        match attempt_build_dxgi() {
            Ok(b) => return Some(b),
            Err(BackendBail::DesktopMismatch) if attempt < DXGI_INIT_MAX_ATTEMPTS => {
                tracing::info!(
                    attempt,
                    max = DXGI_INIT_MAX_ATTEMPTS,
                    "DXGI init: E_ACCESSDENIED (desktop/session transition) — rebinding + retrying before GDI fallback"
                );
                thread::sleep(DXGI_INIT_RETRY_BACKOFF);
            }
            Err(BackendBail::DesktopMismatch) => {
                tracing::warn!(
                    attempts = DXGI_INIT_MAX_ATTEMPTS,
                    "DXGI init: still E_ACCESSDENIED after retries — conceding to GDI for now (5 s re-climb will keep trying)"
                );
                return None;
            }
            Err(e) => {
                tracing::warn!(
                    ?e,
                    "DXGI init failed (non-recoverable) — falling back to GDI BitBlt"
                );
                return None;
            }
        }
    }
    None
}

#[cfg(not(feature = "scrap-capture"))]
fn build_initial_backend() -> Result<ActiveBackend> {
    let gdi = GdiBackend::primary()
        .map_err(|e| anyhow!("GDI fallback init failed and DXGI not compiled in: {e}"))?;
    tracing::info!("system-context capture: backend=GDI (scrap-capture feature not compiled)");
    Ok(ActiveBackend::Gdi(gdi))
}

fn backend_dimensions(b: &ActiveBackend) -> (u32, u32) {
    match b {
        #[cfg(feature = "scrap-capture")]
        ActiveBackend::Dxgi(d) => d.dimensions(),
        ActiveBackend::Gdi(g) => g.dimensions(),
    }
}

/// Human-readable name of the active capture backend, for the worker
/// heartbeat (rc.105 Phase 0 — so a single rc:logs-fetch shows whether
/// capture is on fast DXGI Desktop Duplication or the slow GDI BitBlt
/// fallback, the decisive A-vs-B signal for the hybrid-GPU bug).
fn backend_name(b: &ActiveBackend) -> &'static str {
    match b {
        #[cfg(feature = "scrap-capture")]
        // "dxgi-direct" (adapter-bound, the rc.108 hybrid fix) vs
        // "dxgi-scrap" (auto-adapter fallback) — so a single rc:logs-fetch
        // shows whether the Phase 1 fix actually engaged on a hybrid host.
        ActiveBackend::Dxgi(d) => d.kind(),
        ActiveBackend::Gdi(_) => "gdi",
    }
}

/// Single capture iteration. Branches on the active backend; updates
/// `consecutive_hard` (DXGI HardError counter) so the fallback
/// trip-wire fires after `HARD_ERROR_FALLBACK_THRESHOLD`.
///
/// Returns:
/// * `Ok(Some(frame))` on a real captured frame.
/// * `Ok(None)` on transient / desktop-rebind / access-lost / single
///   HardError — `media_pump`'s idle-keepalive path covers the gap.
/// * `Err(e)` on terminal failure (SessionGone or GDI also failing) —
///   `media_pump` will rebuild the pump.
// Nine parameters, and they are the loop state this single capture iteration
// both reads and advances (three counters, two timers, a delivered flag). A
// struct would only move the same fields behind one name while the caller
// still threads every one of them through `media_pump`, so the allow buys
// clarity nothing. Never surfaced before because the module is behind
// `system-context` and that lane could not compile at all.
#[allow(clippy::too_many_arguments)]
fn capture_one_blocking(
    backend: &mut ActiveBackend,
    consecutive_hard: &mut u32,
    #[cfg_attr(not(feature = "scrap-capture"), allow(unused_variables))]
    consecutive_access_lost: &mut u32,
    consecutive_empty: &mut u64,
    // rc.108 — re-climb timer for the non-permanent GDI fallback. Read +
    // written only on the GDI path (under `scrap-capture`); an unused
    // parameter on the GDI-only build, which Rust does not warn on.
    #[cfg_attr(not(feature = "scrap-capture"), allow(unused_variables))]
    last_dxgi_reclimb: &mut Instant,
    // FR-34 — see the two fields' declarations in worker_main.
    #[cfg_attr(not(feature = "scrap-capture"), allow(unused_variables))]
    backend_built_at: &mut Instant,
    delivered_since_build: &mut bool,
    // FR-34 P2 — one-shot first-frame prime flag (see worker_main). Only read on
    // the DXGI Transient path under `scrap-capture`.
    #[cfg_attr(not(feature = "scrap-capture"), allow(unused_variables))]
    first_frame_primed: &mut bool,
    start: Instant,
    // Phase B — forwarded to GPU-capable DXGI backends; GDI ignores it.
    #[cfg_attr(not(feature = "scrap-capture"), allow(unused_variables))] output_cap: Option<(
        u32,
        u32,
    )>,
) -> CaptureReply {
    // rc.108 — NON-PERMANENT GDI fallback. The doc-comment has claimed
    // since M3 A1 that "every successful GDI frame also re-tries DXGI"
    // but the GDI arm never did — a transient Optimus AccessLost / driver
    // reset that forced us onto the slow ~12 fps GDI BitBlt path pinned us
    // there for the rest of the session. Here we actually do it: if we're
    // on GDI and the re-climb interval has elapsed, rebuild DXGI (the
    // adapter-bound direct backend is preferred). Runs BEFORE the match
    // takes any binding on `backend`, so reassigning it is borrow-clean.
    #[cfg(feature = "scrap-capture")]
    if matches!(backend, ActiveBackend::Gdi(_))
        && last_dxgi_reclimb.elapsed() >= DXGI_RECLIMB_INTERVAL
    {
        *last_dxgi_reclimb = Instant::now();
        if let Some(b) = try_build_dxgi() {
            tracing::info!(
                kind = b.kind(),
                "system-context capture: climbed back from GDI fallback to DXGI"
            );
            *backend = ActiveBackend::Dxgi(b);
            *consecutive_hard = 0;
            *consecutive_access_lost = 0;
            *backend_built_at = Instant::now();
            *delivered_since_build = false;
            // Fall through — the match below now takes the Dxgi arm and
            // attempts a real frame this tick.
        }
    }

    match backend {
        #[cfg(feature = "scrap-capture")]
        ActiveBackend::Dxgi(b) => match b.frame(output_cap) {
            Ok(frame) => {
                *consecutive_hard = 0;
                *consecutive_access_lost = 0;
                *consecutive_empty = 0;
                *delivered_since_build = true;
                Ok(Some(dxgi_to_frame(frame, start)))
            }
            Err(BackendBail::Transient) => {
                *consecutive_hard = 0;
                *consecutive_access_lost = 0;
                *consecutive_empty = consecutive_empty.saturating_add(1);
                // FR-34 P2 — first-frame guarantee. Before the 2 s stuck window,
                // if DXGI has delivered NO frame yet and we have not already
                // primed one, grab a SINGLE GDI BitBlt (which always returns the
                // current screen) once `FIRST_FRAME_GDI_AFTER` has passed — so the
                // controller sees the desktop within ~300 ms of connect to a
                // static screen instead of ~2 s. Deliberately does NOT swap the
                // backend or set `delivered_since_build`: DXGI keeps running and
                // takes over at full quality the instant it delivers a real frame
                // (a merely-slow first frame is never abandoned), and a
                // truly-STUCK DXGI is still caught by `capture_is_stuck` below.
                if first_frame_should_prime(
                    *delivered_since_build,
                    *first_frame_primed,
                    backend_built_at.elapsed(),
                ) && stuck_capture_recovery_enabled()
                {
                    *first_frame_primed = true;
                    match GdiBackend::primary().and_then(|mut g| g.frame()) {
                        Ok(frame) => {
                            tracing::info!(
                                age_ms = backend_built_at.elapsed().as_millis() as u64,
                                "system-context capture: primed first frame via one-shot GDI while DXGI warms up (FR-34 P2)"
                            );
                            return Ok(Some(gdi_to_frame(frame, start)));
                        }
                        Err(e) => {
                            tracing::debug!(
                                %e,
                                "FR-34 P2: one-shot GDI first-frame prime failed; deferring to stuck-recovery"
                            );
                        }
                    }
                }
                // FR-34 — a duplication that has delivered NO frame since it was
                // built, yet keeps returning empty, is STUCK (bound to a stale
                // desktop after a lock→unlock: AcquireNextFrame WAIT_TIMEOUTs
                // forever on a desktop that never changes), not idle. Rebind the
                // input desktop and fall to the always-delivers GDI BitBlt path
                // — the AccessLost arm's proven escape; the DXGI reclimb timer
                // restores DXGI once the desktop settles. GATED on
                // `delivered_since_build` so a WORKING session's idle (the
                // legitimate Transient) is byte-for-byte untouched.
                if capture_is_stuck(*delivered_since_build, backend_built_at.elapsed())
                    && stuck_capture_recovery_enabled()
                {
                    let _ = desktop_rebind::try_change_desktop();
                    match GdiBackend::primary() {
                        Ok(g) => {
                            tracing::warn!(
                                consecutive_empty = *consecutive_empty,
                                stuck_after_s = STUCK_CAPTURE_RECOVERY_AFTER.as_secs(),
                                "system-context capture: DXGI duplication delivered no frames (stuck after a desktop transition) — GDI backstop + desktop rebind (FR-34)"
                            );
                            *backend = ActiveBackend::Gdi(g);
                            *backend_built_at = Instant::now();
                            *delivered_since_build = false;
                            *consecutive_empty = 0;
                            // Let the reclimb timer restore DXGI on the settled desktop.
                            *last_dxgi_reclimb = Instant::now();
                            return Ok(None);
                        }
                        Err(e2) => {
                            tracing::error!(%e2, "system-context capture: GDI backstop init failed while DXGI was stuck (FR-34) — staying on DXGI");
                            // Back off a full window rather than retry every tick.
                            *backend_built_at = Instant::now();
                        }
                    }
                }
                Ok(None)
            }
            Err(BackendBail::DesktopMismatch) => {
                *consecutive_hard = 0;
                *consecutive_access_lost = 0;
                *consecutive_empty = consecutive_empty.saturating_add(1);
                match desktop_rebind::try_change_desktop() {
                    Ok(desktop_rebind::DesktopChange::Switched(name)) => {
                        tracing::info!(%name, "system-context capture: rebound desktop after DXGI DesktopMismatch");
                    }
                    Ok(desktop_rebind::DesktopChange::Unchanged) => {
                        tracing::warn!(
                            "DXGI DesktopMismatch but try_change_desktop reported Unchanged — race or stale binding"
                        );
                    }
                    Err(e) => {
                        tracing::warn!(%e, "desktop rebind failed after DesktopMismatch");
                    }
                }
                Ok(None)
            }
            Err(BackendBail::AccessLost) => {
                *consecutive_hard = 0;
                *consecutive_access_lost = consecutive_access_lost.saturating_add(1);
                *consecutive_empty = consecutive_empty.saturating_add(1);
                // Threshold breach → fall back to GDI immediately. A
                // sustained AccessLost storm during a Win+L cycle is
                // expensive (each recreate is ~30-50ms of GPU work);
                // GDI BitBlt is cheaper and works through the
                // transition. The next Ok(frame) on GDI will reset
                // the counter; the next time DXGI is rebuilt (via
                // pump-rebuild or a session restart) it'll be
                // healthy again.
                if *consecutive_access_lost >= ACCESS_LOST_FALLBACK_THRESHOLD {
                    match GdiBackend::primary() {
                        Ok(g) => {
                            tracing::warn!(
                                threshold = ACCESS_LOST_FALLBACK_THRESHOLD,
                                "DXGI persistent AccessLost — switching to GDI BitBlt fallback (lock-screen / display-compositor transition)"
                            );
                            *backend = ActiveBackend::Gdi(g);
                            *consecutive_access_lost = 0;
                            *backend_built_at = Instant::now();
                            *delivered_since_build = false;
                            return Ok(None);
                        }
                        Err(e2) => {
                            tracing::error!(
                                %e2,
                                "GDI fallback init also failed during AccessLost storm; staying on DXGI"
                            );
                        }
                    }
                }
                // Below threshold: log at WARN for the first 3, debug
                // afterwards to keep the log readable. Desktop may
                // have flipped under us during AccessLost (lock →
                // unlock typically does), so opportunistically rebind.
                if *consecutive_access_lost <= 3 {
                    tracing::warn!(
                        count = *consecutive_access_lost,
                        "DXGI AccessLost — recreating capturer (desktop transition or GPU device-lost)"
                    );
                } else {
                    tracing::debug!(
                        count = *consecutive_access_lost,
                        "DXGI AccessLost (continuing — fallback at {ACCESS_LOST_FALLBACK_THRESHOLD})"
                    );
                }
                if let Err(e) = b.reset() {
                    tracing::warn!(?e, "DXGI reset after AccessLost failed");
                }
                let _ = desktop_rebind::try_change_desktop();
                Ok(None)
            }
            Err(BackendBail::SessionGone) => {
                tracing::error!("DXGI SessionGone — capture pump must rebuild");
                Err(anyhow!(
                    "DXGI Desktop Duplication: session disconnected (SessionGone)"
                ))
            }
            Err(BackendBail::HardError(e)) => {
                *consecutive_hard = consecutive_hard.saturating_add(1);
                *consecutive_access_lost = 0;
                *consecutive_empty = consecutive_empty.saturating_add(1);
                tracing::warn!(
                    %e,
                    count = *consecutive_hard,
                    "DXGI hard error"
                );
                if *consecutive_hard >= HARD_ERROR_FALLBACK_THRESHOLD {
                    match GdiBackend::primary() {
                        Ok(g) => {
                            tracing::warn!(
                                threshold = HARD_ERROR_FALLBACK_THRESHOLD,
                                "DXGI failed past threshold — switching to GDI BitBlt fallback"
                            );
                            *backend = ActiveBackend::Gdi(g);
                            *consecutive_hard = 0;
                            *backend_built_at = Instant::now();
                            *delivered_since_build = false;
                        }
                        Err(e2) => {
                            tracing::error!(
                                %e2,
                                "GDI fallback init also failed; capture pump must rebuild"
                            );
                            return Err(anyhow!(
                                "DXGI repeatedly failed and GDI fallback init also failed: {e2}"
                            ));
                        }
                    }
                }
                Ok(None)
            }
        },
        ActiveBackend::Gdi(g) => {
            // rc.90 — proactively re-bind the input desktop BEFORE each
            // GDI BitBlt. The capture thread bound once at worker startup
            // (worker_main step 2), but the displayed input desktop flips
            // afterwards (Win+L lock/unlock, UAC secure desktop, fast-
            // user-switch). The DXGI arm rebinds on its errors; the GDI
            // arm NEVER did, so a stale binding made BitBlt fail
            // ERROR_ACCESS_DENIED ("Zugriff verweigert", os error 5)
            // ~25×/s forever with no recovery — video never rendered AND
            // the spam buried the throughput lines in the log upload
            // (field: WINHOST-E). `SetThreadDesktop` is per-thread and this
            // always runs on `roomlerd-system-capture`, so the
            // rebind sticks for the BitBlt that follows. `try_change_desktop`
            // dedupes (only SetThreadDesktop when the desktop actually
            // changed), so steady-state cost is one OpenInputDesktop
            // syscall (µs) per frame — negligible at GDI-fallback rates.
            match desktop_rebind::try_change_desktop() {
                Ok(desktop_rebind::DesktopChange::Switched(name)) => {
                    tracing::info!(
                        %name,
                        "system-context capture (GDI): rebound input desktop before BitBlt"
                    );
                    *consecutive_hard = 0;
                }
                Ok(desktop_rebind::DesktopChange::Unchanged) => {}
                Err(e) => {
                    // Can't reach the input desktop AT ALL — almost
                    // always the worker isn't on WinSta0 or isn't in the
                    // active session. A per-thread rebind can't fix that;
                    // surface it (rate-limited) so the field log shows the
                    // REAL blocker (session/winstation) instead of BitBlt
                    // spam. Distinguishes "stale binding" (recoverable
                    // here) from "wrong session" (needs a spawn fix).
                    *consecutive_hard = consecutive_hard.saturating_add(1);
                    if *consecutive_hard <= 3 || consecutive_hard.is_multiple_of(150) {
                        tracing::warn!(
                            %e,
                            count = *consecutive_hard,
                            "system-context capture (GDI): cannot reach input desktop — video stalled (worker likely not on WinSta0 / wrong session)"
                        );
                    }
                    return Ok(None);
                }
            }
            match g.frame() {
                Ok(frame) => {
                    *consecutive_hard = 0;
                    *consecutive_empty = 0;
                    *delivered_since_build = true;
                    Ok(Some(gdi_to_frame(frame, start)))
                }
                Err(e) => {
                    *consecutive_hard = consecutive_hard.saturating_add(1);
                    // Rate-limit: WARN first 3, then ~once / 5 s (150
                    // frames @ 30 fps). Pre-rc.90 this logged EVERY frame.
                    if *consecutive_hard <= 3 || consecutive_hard.is_multiple_of(150) {
                        tracing::warn!(
                            %e,
                            count = *consecutive_hard,
                            "system-context capture (GDI): BitBlt failed after desktop rebind — retrying"
                        );
                    }
                    // Return Ok(None), NOT Err. The worker loop doesn't
                    // rebuild the backend on Err (it just propagates one
                    // failed frame the media pump skips anyway), so Err
                    // bought nothing but a noisier log. Ok(None) is a
                    // clean keepalive tick; the proactive rebind above
                    // recovers automatically once the desktop is reachable.
                    Ok(None)
                }
            }
        }
    }
}

#[cfg(feature = "scrap-capture")]
fn dxgi_to_frame(f: DxgiFrame, start: Instant) -> Frame {
    Frame {
        width: f.width,
        height: f.height,
        stride: f.stride,
        pixel_format: PixelFormat::Bgra,
        data: f.bytes,
        monotonic_us: start.elapsed().as_micros() as u64,
        monitor: 0,
        // P8a — the DXGI-direct backend reads the duplication metadata
        // and reports authoritative damage; the scrap-wrapped backend
        // can't (scrap's public API drops the frame info) and carries
        // Unknown through the same field.
        damage: f.damage,
        source: f.source,
    }
}

fn gdi_to_frame(f: GdiFrame, start: Instant) -> Frame {
    Frame {
        width: f.width,
        height: f.height,
        stride: f.stride,
        pixel_format: PixelFormat::Bgra,
        data: f.bytes,
        monotonic_us: start.elapsed().as_micros() as u64,
        monitor: 0,
        // GDI BitBlt has no damage concept — and it emits a frame on
        // EVERY poll, so "a frame arrived" isn't motion evidence either.
        damage: crate::capture::Damage::Unknown,
        source: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FR-34 — the stuck-vs-idle decision, the whole point of which is that a
    /// backend that has EVER delivered a frame is never treated as stuck (that
    /// is a working session gone idle), while one that has delivered nothing
    /// past the timeout is. Locks the CORPLAP-1 incident: 0 delivered, long age.
    #[test]
    fn capture_is_stuck_only_when_nothing_was_ever_delivered() {
        let long = STUCK_CAPTURE_RECOVERY_AFTER + Duration::from_millis(1);
        let short = STUCK_CAPTURE_RECOVERY_AFTER - Duration::from_millis(1);
        // never delivered + past the window ⇒ stuck (the incident)
        assert!(capture_is_stuck(false, long));
        // never delivered but still within the window ⇒ not yet (a slow first frame)
        assert!(!capture_is_stuck(false, short));
        // delivered ⇒ never stuck, no matter how long the idle
        assert!(!capture_is_stuck(true, long));
        assert!(!capture_is_stuck(true, Duration::from_secs(3600)));
        // exactly at the threshold counts (>=)
        assert!(capture_is_stuck(false, STUCK_CAPTURE_RECOVERY_AFTER));
    }

    #[test]
    fn first_frame_primes_before_delivery_and_before_the_stuck_window() {
        let after = FIRST_FRAME_GDI_AFTER + Duration::from_millis(1);
        let before = FIRST_FRAME_GDI_AFTER - Duration::from_millis(1);
        // never delivered, not yet primed, past the short window ⇒ prime once
        assert!(first_frame_should_prime(false, false, after));
        // still inside the short window ⇒ let DXGI try first
        assert!(!first_frame_should_prime(false, false, before));
        // already primed this session ⇒ never re-prime
        assert!(!first_frame_should_prime(false, true, after));
        // DXGI already delivered a real frame ⇒ no GDI prime needed
        assert!(!first_frame_should_prime(true, false, after));
        // The prime window MUST be strictly shorter than the stuck window, so a
        // static screen shows a GDI first frame long before it is declared stuck
        // — and a stuck DXGI still trips `capture_is_stuck` (prime does not set
        // `delivered_since_build`).
        assert!(FIRST_FRAME_GDI_AFTER < STUCK_CAPTURE_RECOVERY_AFTER);
    }

    #[test]
    fn hard_error_threshold_matches_rustdesk() {
        // Lock the trip-wire constant. RustDesk's
        // video_service.rs:851-856 uses 3; field tuning below that
        // gives premature GDI fallbacks on hybrid GPU laptops where
        // a single transient HardError isn't actually persistent.
        assert_eq!(HARD_ERROR_FALLBACK_THRESHOLD, 3);
    }

    #[test]
    fn primary_returns_send_handle() {
        // Compile-time check that SystemContextCapture is Send (the
        // ScreenCapture trait requires Send). The cmd_tx is the only
        // field that affects Send-ness; std_mpsc::Sender<T> is Send
        // when T is Send, and oneshot::Sender<Result<...>> is Send.
        fn assert_send<T: Send>() {}
        assert_send::<SystemContextCapture>();
    }

    #[test]
    fn screen_capture_trait_is_implemented() {
        // Compile-time check that the trait impl actually compiles
        // against the real ScreenCapture surface.
        fn assert_impl<T: ScreenCapture>() {}
        assert_impl::<SystemContextCapture>();
    }

    #[cfg(feature = "scrap-capture")]
    #[test]
    fn primary_does_not_panic_under_test_runner() {
        // On a real Win11 desktop runner the worker thread will
        // start, attach to WinSta0 (idempotent under user context),
        // and DXGI primary should succeed. CI without a GPU may
        // fail at DXGI primary; we accept either outcome — lock
        // against panic, not specific success.
        let res = SystemContextCapture::primary(30, DownscalePolicy::default());
        // Drop immediately; the worker thread will exit when the
        // cmd_rx side hangs up.
        drop(res);
    }
}
