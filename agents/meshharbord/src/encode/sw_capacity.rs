// SPDX-License-Identifier: MPL-2.0
//! What this host's software VP9 4:4:4 encoder (libvpx) delivers, as a real
//! session measured it.
//!
//! A probe proves an OPEN; only a session proves a CELL. libvpx opens on every
//! host, so the start-up probe advertises it everywhere — and a viewer's
//! automatic pick, on the Priority dial's Sharper, takes it whenever the agent
//! has no hardware encoder. On a one-core server that pick was the worst one:
//! under motion, even after the software resolution tier had shrunk the frame
//! to its 1024 px floor, the session delivered 11-12 fps (the pointer arrived
//! long before the window it dragged), while H.264 cost half as much a frame.
//!
//! So the VP9 4:4:4 pump records what it actually delivered when it was at
//! the floor, under motion, and still below [`PICK_FLOOR_FPS`]. The verdict
//! rides the libvpx cell as `sustain_fps` (and the live `rc:video-info`), and
//! the viewer's automatic pick skips the cell; an explicit pick still gets it.
//! It is kept next to the daemon's logs, keyed on the hardware fingerprint,
//! for [`TTL_SECS`] — a resized VM or a new CPU is measured again.
//!
//! Kill switch: `MESHHARBORD_SW_CAPACITY=0` (neither recorded nor advertised).

use std::path::{Path, PathBuf};
use std::sync::RwLock;

use serde::{Deserialize, Serialize};
use tunnel_core::env::node_env;

/// Below this delivered rate an automatic pick should leave the cell; a
/// verdict is recorded only under it.
pub const PICK_FLOOR_FPS: u32 = 20;

/// How long a verdict holds before a session may measure again.
pub const TTL_SECS: u64 = 30 * 24 * 3600;

const FILE_NAME: &str = "sw-capacity.json";

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
struct Record {
    /// `encode::hwid::fingerprint()` when measured (`None` where the platform
    /// has none: the record then holds only for this process).
    hardware: Option<String>,
    libvpx_444_fps: u32,
    long_edge: u32,
    measured_unix: u64,
}

/// `None` = not loaded yet; `Some(None)` = loaded, no verdict.
static STATE: RwLock<Option<Option<Record>>> = RwLock::new(None);

fn enabled() -> bool {
    !matches!(
        node_env("SW_CAPACITY").as_deref(),
        Some("0") | Some("false") | Some("off")
    )
}

fn path() -> Option<PathBuf> {
    crate::logging::log_dir()
        .or_else(crate::logging::resolve_log_dir)
        .map(|d| d.join(FILE_NAME))
}

fn now_unix() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A stored verdict still speaks for this host now.
fn holds(rec: &Record, hardware_now: Option<&str>, now: u64) -> bool {
    rec.libvpx_444_fps < PICK_FLOOR_FPS
        && rec.hardware.as_deref() == hardware_now
        && now.saturating_sub(rec.measured_unix) < TTL_SECS
        && rec.measured_unix <= now + 3600
}

fn load(p: &Path, hardware_now: Option<&str>, now: u64) -> Option<Record> {
    let rec: Record = serde_json::from_slice(&std::fs::read(p).ok()?).ok()?;
    holds(&rec, hardware_now, now).then_some(rec)
}

fn current() -> Option<Record> {
    if let Some(s) = STATE.read().unwrap_or_else(|e| e.into_inner()).as_ref() {
        return s.clone();
    }
    let loaded = path().and_then(|p| load(&p, super::hwid::fingerprint().as_deref(), now_unix()));
    *STATE.write().unwrap_or_else(|e| e.into_inner()) = Some(loaded.clone());
    loaded
}

/// The delivered rate a session measured for libvpx VP9 4:4:4 at its floor,
/// when it was below [`PICK_FLOOR_FPS`]; `None` otherwise (and when switched off).
pub fn libvpx_444_sustain_fps() -> Option<u32> {
    if !enabled() {
        return None;
    }
    current().map(|r| r.libvpx_444_fps)
}

/// Record a session's verdict: libvpx VP9 4:4:4 delivered `fps` at
/// `long_edge` under motion, at the smallest tier. Only a rate below
/// [`PICK_FLOOR_FPS`] is kept. Returns true when the advertised value changed.
pub fn record_libvpx_444(fps: u32, long_edge: u32) -> bool {
    if !enabled() || fps >= PICK_FLOOR_FPS {
        return false;
    }
    let before = current().map(|r| r.libvpx_444_fps);
    let rec = Record {
        hardware: super::hwid::fingerprint(),
        libvpx_444_fps: fps,
        long_edge,
        measured_unix: now_unix(),
    };
    if let Some(p) = path()
        && let Ok(bytes) = serde_json::to_vec(&rec)
    {
        let tmp = p.with_extension("json.tmp");
        if std::fs::write(&tmp, bytes).is_ok() {
            let _ = std::fs::rename(&tmp, &p);
        }
    }
    *STATE.write().unwrap_or_else(|e| e.into_inner()) = Some(Some(rec));
    before != Some(fps)
}

/// The live verdict for the VP9 4:4:4 pump: delivered frame rates of motion
/// windows at the resolution floor. Five in a row under [`PICK_FLOOR_FPS`]
/// make a verdict (their mean); a motion window at or above it starts over.
/// Windows that are not at the floor or carry no motion say nothing.
#[derive(Default)]
pub struct Verdict {
    run: Vec<f32>,
    reported: bool,
}

/// Motion windows in a row before a verdict.
pub const VERDICT_WINDOWS: usize = 5;

impl Verdict {
    /// Fold one heartbeat window. Returns the delivered rate to record once.
    pub fn observe(&mut self, at_floor: bool, motion: bool, delivered_fps: f32) -> Option<u32> {
        if self.reported || !at_floor || !motion || !delivered_fps.is_finite() {
            return None;
        }
        if delivered_fps >= PICK_FLOOR_FPS as f32 {
            self.run.clear();
            return None;
        }
        self.run.push(delivered_fps);
        if self.run.len() < VERDICT_WINDOWS {
            return None;
        }
        self.reported = true;
        let mean = self.run.iter().sum::<f32>() / self.run.len() as f32;
        Some(mean.round().max(1.0) as u32)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The one-core server: five motion windows at the floor, 11-12 fps.
    #[test]
    fn a_slow_floor_under_motion_makes_one_verdict() {
        let mut v = Verdict::default();
        for fps in [11.5, 12.0, 11.0, 12.5] {
            assert_eq!(v.observe(true, true, fps), None);
        }
        assert_eq!(v.observe(true, true, 11.0), Some(12));
        assert_eq!(v.observe(true, true, 11.0), None, "once");
    }

    #[test]
    fn only_motion_at_the_floor_counts() {
        let mut v = Verdict::default();
        for _ in 0..10 {
            assert_eq!(v.observe(false, true, 8.0), None, "not at the floor");
            assert_eq!(v.observe(true, false, 8.0), None, "static");
        }
        for _ in 0..4 {
            v.observe(true, true, 10.0);
        }
        assert_eq!(
            v.observe(true, true, 25.0),
            None,
            "a fast window starts over"
        );
        for _ in 0..4 {
            assert_eq!(v.observe(true, true, 10.0), None);
        }
        assert_eq!(v.observe(true, true, 10.0), Some(10));
    }

    #[test]
    fn a_verdict_holds_for_this_hardware_and_this_month() {
        let rec = Record {
            hardware: Some("cpu-a".into()),
            libvpx_444_fps: 12,
            long_edge: 1024,
            measured_unix: 1_000_000,
        };
        assert!(holds(&rec, Some("cpu-a"), 1_000_000 + 3600));
        assert!(!holds(&rec, Some("cpu-b"), 1_000_000), "new hardware");
        assert!(!holds(&rec, Some("cpu-a"), 1_000_000 + TTL_SECS), "expired");
        assert!(
            !holds(&rec, Some("cpu-a"), 1_000_000 - 7200),
            "from the future"
        );
        let fast = Record {
            libvpx_444_fps: 25,
            ..rec.clone()
        };
        assert!(
            !holds(&fast, Some("cpu-a"), 1_000_000),
            "fast enough is no verdict"
        );
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join(FILE_NAME);
        std::fs::write(&p, serde_json::to_vec(&rec).unwrap()).unwrap();
        assert_eq!(load(&p, Some("cpu-a"), 1_000_100), Some(rec));
        std::fs::write(&p, b"{not json").unwrap();
        assert_eq!(load(&p, Some("cpu-a"), 1_000_100), None);
    }
}
