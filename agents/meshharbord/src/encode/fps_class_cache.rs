// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-119 P2b — the rate-class cache: what trials concluded about this host.
//!
//! A frame rate above 60 is granted without a trial only for a class a session
//! has PROVEN (`encode::frame_rate::TrialMeter`), and never again for one that
//! FAILED. Both verdicts are facts about this build on this hardware with
//! these knobs. So they live next to the encoder probe's cache, under the very
//! same key (`caps_cache::CacheKey`: the build, the hardware fingerprint, a
//! hash of every `ROOMLERD_*` knob), and any change of key forgets them all.
//!
//! Rules:
//! - **A key mismatch, an unreadable file or another format version reads as
//!   empty**: an unproven host, the safe answer. It is never an error.
//! - **The newest verdict for a class wins**: a later trial overwrites an
//!   earlier one.
//! - **`ROOMLERD_CAPS_CACHE=0` switches this off too**: no read, no write.
//!   Every class is then unproven on every start, and trials repeat.
//! - **A verdict older than [`MAX_AGE_SECS`] is forgotten**: the safety net for
//!   a dependency the key does not model, as for the probe cache.

use super::caps_cache::{self, CacheKey};
use super::frame_rate::{ClassKey, Verdict};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub(crate) const FILE_NAME: &str = "fps-class-cache.json";
/// Bumped when the file's meaning changes; an older file reads as empty.
const FORMAT_VERSION: u32 = 1;
/// The same week as the probe cache's.
pub(crate) const MAX_AGE_SECS: u64 = caps_cache::MAX_AGE_SECS;

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub(crate) struct Entry {
    pub class: ClassKey,
    pub verdict: Verdict,
    pub at_unix: u64,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub(crate) struct CacheFile {
    pub version: u32,
    pub key: CacheKey,
    pub classes: Vec<Entry>,
}

/// Next to the probe cache, in the daemon's log directory. `None` when the
/// cache is switched off (`ROOMLERD_CAPS_CACHE=0`), so a caller with no path
/// neither reads nor writes.
pub(crate) fn path() -> Option<PathBuf> {
    if !caps_cache::enabled() {
        return None;
    }
    caps_cache::path().map(|p| p.with_file_name(FILE_NAME))
}

/// The verdicts that still hold under `key` at `now_unix`; empty on any miss.
pub(crate) fn load(path: &Path, key: &CacheKey, now_unix: u64) -> Vec<Entry> {
    let Ok(text) = std::fs::read_to_string(path) else {
        return Vec::new();
    };
    let Ok(file) = serde_json::from_str::<CacheFile>(&text) else {
        return Vec::new();
    };
    if file.version != FORMAT_VERSION || &file.key != key {
        return Vec::new();
    }
    file.classes
        .into_iter()
        .filter(|e| now_unix.saturating_sub(e.at_unix) <= MAX_AGE_SECS)
        .collect()
}

/// The cached verdict for one class, if there is one. The pump hands every
/// entry to `frame_rate::RateState`, which keeps the newest per class itself;
/// this is the same rule, for the tests.
#[cfg(test)]
pub(crate) fn verdict_for(entries: &[Entry], class: &ClassKey) -> Option<Verdict> {
    entries
        .iter()
        .filter(|e| &e.class == class)
        .max_by_key(|e| e.at_unix)
        .map(|e| e.verdict)
}

/// Record a trial's verdict: replace that class's entry, keep the rest, and
/// write the file atomically (temp file, then rename), as the probe cache
/// does.
pub(crate) fn record(
    path: &Path,
    key: &CacheKey,
    class: ClassKey,
    verdict: Verdict,
    now_unix: u64,
) -> std::io::Result<()> {
    let mut classes = load(path, key, now_unix);
    classes.retain(|e| e.class != class);
    classes.push(Entry {
        class,
        verdict,
        at_unix: now_unix,
    });
    let file = CacheFile {
        version: FORMAT_VERSION,
        key: key.clone(),
        classes,
    };
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let json = serde_json::to_vec_pretty(&file).map_err(std::io::Error::other)?;
    let tmp = path.with_extension(format!("json.{}.tmp", std::process::id()));
    std::fs::write(&tmp, json)?;
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(build: &str) -> CacheKey {
        CacheKey {
            build: build.to_string(),
            hardware: "gpu-a/driver-1/os-1".to_string(),
            knobs: "k".to_string(),
        }
    }

    fn class(encoder: &str, fps: u32) -> ClassKey {
        ClassKey {
            backend: "scrap".to_string(),
            refresh_hz: 120,
            encoder: encoder.to_string(),
            long_edge: 3840,
            fps,
        }
    }

    #[test]
    fn a_recorded_verdict_is_read_back_under_the_same_key() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join(FILE_NAME);
        let k = key("0.4.150/1/1");
        record(
            &p,
            &k,
            class("hevc_videotoolbox", 120),
            Verdict::Proven,
            1_000,
        )
        .unwrap();
        record(
            &p,
            &k,
            class("hevc_videotoolbox", 144),
            Verdict::Failed,
            1_001,
        )
        .unwrap();
        let entries = load(&p, &k, 1_002);
        assert_eq!(
            verdict_for(&entries, &class("hevc_videotoolbox", 120)),
            Some(Verdict::Proven)
        );
        assert_eq!(
            verdict_for(&entries, &class("hevc_videotoolbox", 144)),
            Some(Verdict::Failed)
        );
        assert_eq!(verdict_for(&entries, &class("hevc_nvenc", 120)), None);
    }

    /// A later trial of the same class replaces the earlier verdict.
    #[test]
    fn the_newest_verdict_for_a_class_wins() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join(FILE_NAME);
        let k = key("b");
        record(&p, &k, class("av1_nvenc", 120), Verdict::Failed, 10).unwrap();
        record(&p, &k, class("av1_nvenc", 120), Verdict::Proven, 20).unwrap();
        let entries = load(&p, &k, 30);
        assert_eq!(entries.len(), 1);
        assert_eq!(
            verdict_for(&entries, &class("av1_nvenc", 120)),
            Some(Verdict::Proven)
        );
    }

    /// A new build, new hardware or new knobs forget every verdict: the host is
    /// unproven again, which is the safe answer.
    #[test]
    fn another_key_reads_as_empty() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join(FILE_NAME);
        record(
            &p,
            &key("old-build"),
            class("hevc_qsv", 120),
            Verdict::Proven,
            10,
        )
        .unwrap();
        assert!(load(&p, &key("new-build"), 11).is_empty());
        let other_hw = CacheKey {
            hardware: "gpu-b".to_string(),
            ..key("old-build")
        };
        assert!(load(&p, &other_hw, 11).is_empty());
    }

    /// No file, a damaged file, or a verdict older than a week: empty.
    #[test]
    fn a_miss_of_any_kind_reads_as_empty() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join(FILE_NAME);
        let k = key("b");
        assert!(load(&p, &k, 0).is_empty(), "no file");
        std::fs::write(&p, b"{ not json").unwrap();
        assert!(load(&p, &k, 0).is_empty(), "a damaged file");
        record(&p, &k, class("hevc_qsv", 120), Verdict::Proven, 100).unwrap();
        assert_eq!(
            load(&p, &k, 100 + MAX_AGE_SECS).len(),
            1,
            "a week old still holds"
        );
        assert!(
            load(&p, &k, 101 + MAX_AGE_SECS).is_empty(),
            "older than a week"
        );
    }
}
