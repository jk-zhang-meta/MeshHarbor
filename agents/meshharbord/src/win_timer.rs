// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Windows multimedia timer resolution.
//!
//! By default a Windows process runs at the *system* timer resolution,
//! which is **15.6 ms (≈64 Hz)** unless some process on the machine has
//! requested finer. Every `tokio::time::sleep`, every timer-park wakeup,
//! and — critically — every cross-thread reschedule that lands while a
//! tokio worker is parked in `park_timeout` is therefore quantized to
//! ~15.6 ms boundaries.
//!
//! For the SystemContext capture path this is catastrophic. The FFmpeg
//! DataChannel pump (`peer::media_pump_ffmpeg_dc`) paces with a
//! `tokio::time::sleep` floor and a *tiny* HW encode (vp9_qsv / hevc_qsv
//! ~4 ms), so the loop spends most of each frame parked on a timer. With
//! 15.6 ms granularity the floor sleep AND the per-frame capture oneshot
//! round-trip (`SystemContextCapture::next_frame`: mpsc cmd → worker
//! thread → scrap `frame()` 0.85 ms → oneshot reply → tokio reschedule)
//! both round *up* to 15.6 ms ticks. Field data (WINHOST-E, 2026-05-30)
//! showed the round-trip ballooning to ~45 ms/frame under motion despite
//! the worker-side scrap call measuring 0.85 ms — i.e. ~44 ms was pure
//! timer/scheduler quantization. Result: ~12 fps under motion.
//!
//! The slow libvpx VP9-4:4:4 pump (`media_pump_vp9_444_dc`) never hit
//! this: its 40-120 ms *CPU-bound* SW encode keeps the worker thread hot
//! and off the timer, so the 15.6 ms quantization is a small fraction of
//! its much longer loop. That is why the HW (vp9_qsv, 4 ms encode) path
//! was paradoxically *slower* (12 fps) than the SW (libvpx, 80 ms encode)
//! path (15-25 fps) on the same host.
//!
//! `timeBeginPeriod(1)` drops the resolution to 1 ms — the exact call
//! RustDesk, OBS, and Chrome (during media playback) make for precisely
//! this reason. Held for the process lifetime via [`TimerResolutionGuard`];
//! the matching `timeEndPeriod` runs on drop (best-effort — process exit
//! restores the default anyway).
//!
//! Scope note: on Windows 10 2004+ `timeBeginPeriod` is per-process, so
//! this does not raise the global system timer rate for other processes.
//! A session-0 / background process *can* have its request ignored under
//! aggressive power throttling (EcoQoS); if the field heartbeat's
//! `avg_capture_ms` does NOT drop after this ships, the follow-up is a
//! `SetProcessInformation(ProcessPowerThrottling, …IGNORE_TIMER_RESOLUTION)`
//! opt-out. We ship the standard call first and let the heartbeat tell us
//! whether the opt-out is needed.

#![cfg(target_os = "windows")]

use windows_sys::Win32::Media::{TIMECAPS, timeBeginPeriod, timeEndPeriod, timeGetDevCaps};

/// `timeBeginPeriod` / `timeGetDevCaps` success sentinel (`TIMERR_NOERROR`).
const TIMERR_NOERROR: u32 = 0;

/// RAII guard holding a `timeBeginPeriod(period_ms)` request for its
/// lifetime. Dropping it calls the matching `timeEndPeriod`. Hold one in
/// `main()` for the whole process so every `tokio::time::sleep`,
/// timer-park wakeup, and cross-thread reschedule runs at the requested
/// resolution rather than the 15.6 ms Windows default.
#[derive(Debug)]
pub struct TimerResolutionGuard {
    period_ms: u32,
    /// True when `timeBeginPeriod` returned `TIMERR_NOERROR`. When false
    /// the drop is a no-op (we never successfully began the period).
    active: bool,
    /// Device-supported minimum period (ms) from `timeGetDevCaps`, for
    /// the startup diagnostic. 0 if the caps query failed.
    device_min_ms: u32,
    /// Device-supported maximum period (ms) from `timeGetDevCaps`. 0 if
    /// the caps query failed.
    device_max_ms: u32,
}

impl TimerResolutionGuard {
    /// Request 1 ms timer resolution. Always returns a guard; check
    /// [`active`](Self::active) for whether the OS accepted the request.
    pub fn request_1ms() -> Self {
        Self::request(1)
    }

    /// Request `period_ms` timer resolution. The platform clamps the
    /// effective period to the device's supported `[min, max]` range
    /// (read here purely for the diagnostic).
    pub fn request(period_ms: u32) -> Self {
        // Read device caps first so the startup log can report the
        // supported range even if `timeBeginPeriod` itself fails.
        let (device_min_ms, device_max_ms) = device_period_range();
        // SAFETY: `timeBeginPeriod` is a documented, thread-safe winmm
        // call taking a scalar period; it touches no Rust-owned memory.
        let rc = unsafe { timeBeginPeriod(period_ms) };
        TimerResolutionGuard {
            period_ms,
            active: rc == TIMERR_NOERROR,
            device_min_ms,
            device_max_ms,
        }
    }

    /// Whether `timeBeginPeriod` accepted the request.
    pub fn active(&self) -> bool {
        self.active
    }

    /// The requested period in milliseconds.
    pub fn period_ms(&self) -> u32 {
        self.period_ms
    }

    /// Device-supported minimum period (ms), or 0 if the caps query failed.
    pub fn device_min_ms(&self) -> u32 {
        self.device_min_ms
    }

    /// Device-supported maximum period (ms), or 0 if the caps query failed.
    pub fn device_max_ms(&self) -> u32 {
        self.device_max_ms
    }
}

impl Drop for TimerResolutionGuard {
    fn drop(&mut self) {
        if self.active {
            // SAFETY: matches the successful `timeBeginPeriod` in `request`.
            unsafe {
                timeEndPeriod(self.period_ms);
            }
        }
    }
}

/// Read the platform timer device's supported period range via
/// `timeGetDevCaps`. Returns `(min_ms, max_ms)`, or `(0, 0)` if the call
/// fails — the guard still functions; only the diagnostic loses detail.
fn device_period_range() -> (u32, u32) {
    // SAFETY: `TIMECAPS` is a plain `repr(C)` POD (two u32s); zeroing is a
    // valid initial state for the out-param.
    let mut tc: TIMECAPS = unsafe { std::mem::zeroed() };
    // SAFETY: `timeGetDevCaps` fills the `TIMECAPS` we own; the size
    // argument matches the struct we pass.
    let rc = unsafe { timeGetDevCaps(&mut tc, std::mem::size_of::<TIMECAPS>() as u32) };
    if rc == TIMERR_NOERROR {
        (tc.wPeriodMin, tc.wPeriodMax)
    } else {
        (0, 0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Smoke test: the FFI round-trips without panicking and the guard
    /// reports a coherent requested period. We don't assert hard on
    /// `active()` or the device range because a CI VM's timer device and
    /// pre-existing period requests are non-deterministic.
    #[test]
    fn request_1ms_does_not_panic_and_drops_clean() {
        let g = TimerResolutionGuard::request_1ms();
        assert_eq!(g.period_ms(), 1);
        let _ = g.active();
        let _ = g.device_min_ms();
        let _ = g.device_max_ms();
        // On a real Win10+ host the timer device supports 1 ms; only
        // assert this when the caps query actually returned something so
        // a stripped CI image (which may report (0,0)) doesn't fail.
        if g.device_min_ms() != 0 {
            assert!(
                g.device_min_ms() <= 1,
                "expected ≤1ms min period on a real host"
            );
        }
        // Drop runs `timeEndPeriod` when active — must not panic.
    }
}
