// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-77 P3 — the encoder probe cache.
//!
//! The matrix probe opens every encoder × chroma cell for real (P1): 3.9 s on
//! the dev box, 5.4 s on CORPLAP-3, paid on every daemon start for an answer
//! that changes only when the GPU, its driver, the OS build or the meshharbord
//! build changes. This caches the CHILD PROBE's answer on disk under a key
//! made of exactly those, and re-probes on any mismatch or after
//! [`MAX_AGE_SECS`].
//!
//! Rules, each load-bearing:
//! - **Only a result with at least one HARDWARE cell is cached.** A
//!   no-hardware answer is the cheap case anyway (every open fails fast), and
//!   it is the answer a boot-time driver race produces — a service that starts
//!   before the display driver is up — which must not be frozen for a week.
//! - **Only the driver-derived fields come from the cache** (`hw_encoders`,
//!   `codecs`, `transports`, `hevc_chroma`, `vp9_chroma`, `video_cells`, the
//!   vp9_qsv IDR verdict). Permissions, the GUI-session state, the file /
//!   clipboard / app verbs and the RPC verbs are recomputed on every start:
//!   they change without any driver changing (`caps::merge_cached`).
//! - **`probe_ms` on a hit is the CACHED probe's duration** and
//!   `probe_cached` says so, so the fleet read of probe cost keeps meaning.
//! - **The key hashes every `MESHHARBORD_*` knob** of the process (env + the S2
//!   config fallbacks): a denylist edit, `MESHHARBORD_DC_H264=0`, an encoder
//!   preference all change what the probe would answer. Hashed, never stored
//!   in clear — an env block can carry a token.
//! - **`MESHHARBORD_CAPS_CACHE=0`** (config `caps_cache = false`) disables the
//!   read AND the write; the `caps-probe` child never touches the file.

use meshharbor_remote_control::models::AgentCaps;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// A probe older than this is repeated even under an unchanged key: the
/// safety net for a dependency the key does not model.
pub(crate) const MAX_AGE_SECS: u64 = 7 * 24 * 3600;
pub(crate) const FILE_NAME: &str = "caps-cache.json";
/// Bumped when the file's meaning changes; an older file is a miss, not an
/// error.
const FORMAT_VERSION: u32 = 1;

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub(crate) struct CacheKey {
    /// `<crate version>/<exe length>/<exe mtime>` — a dev build with the
    /// same version number is a different build.
    pub build: String,
    /// [`super::hwid::fingerprint`]: GPUs, driver versions, OS build.
    pub hardware: String,
    /// SHA-256 over the sorted `MESHHARBORD_*` knobs (env + config fallbacks).
    pub knobs: String,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub(crate) struct CacheFile {
    pub version: u32,
    pub key: CacheKey,
    pub probed_at_unix: u64,
    pub probe_ms: u32,
    pub caps: AgentCaps,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vp9_qsv_idr: Option<(bool, bool)>,
}

impl CacheFile {
    pub(crate) fn new(
        key: CacheKey,
        probed_at_unix: u64,
        probe_ms: u32,
        caps: AgentCaps,
        vp9_qsv_idr: Option<(bool, bool)>,
    ) -> Self {
        Self {
            version: FORMAT_VERSION,
            key,
            probed_at_unix,
            probe_ms,
            caps,
            vp9_qsv_idr,
        }
    }
}

/// Why the cache did not answer. Logged as a reason, never an error: every
/// miss is followed by the probe the cache stands in front of.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum Miss {
    NoFile,
    Unreadable(String),
    FormatVersion(u32),
    Build,
    Hardware,
    Knobs,
    Stale { age_secs: u64 },
}

impl Miss {
    pub(crate) fn reason(&self) -> String {
        match self {
            Miss::NoFile => "no cache file (first start on this build, or it was cleared)".into(),
            Miss::Unreadable(e) => format!("cache file unreadable: {e}"),
            Miss::FormatVersion(v) => {
                format!("cache format {v} (this build writes {FORMAT_VERSION})")
            }
            Miss::Build => "meshharbord build changed".into(),
            Miss::Hardware => "GPU / driver / OS build changed".into(),
            Miss::Knobs => "a MESHHARBORD_* knob changed".into(),
            Miss::Stale { age_secs } => {
                format!("cached probe is {age_secs} s old (max {MAX_AGE_SECS})")
            }
        }
    }
}

/// `MESHHARBORD_CAPS_CACHE=0` / `caps_cache = false` switches the cache off.
pub(crate) fn enabled() -> bool {
    tunnel_core::env::node_env("CAPS_CACHE")
        .map(|v| {
            !matches!(
                v.trim().to_ascii_lowercase().as_str(),
                "0" | "false" | "off" | "no"
            )
        })
        .unwrap_or(true)
}

/// Next to the daemon's logs: a directory this identity can already write,
/// on every platform and for the SCM service too (`service-logs`).
pub(crate) fn path() -> Option<PathBuf> {
    crate::logging::log_dir()
        .or_else(crate::logging::resolve_log_dir)
        .map(|d| d.join(FILE_NAME))
}

/// `None` when this platform has no hardware fingerprint — no key, no cache.
pub(crate) fn current_key() -> Option<CacheKey> {
    let hardware = super::hwid::fingerprint()?;
    Some(CacheKey {
        build: build_identity(),
        hardware,
        knobs: knobs_hash(),
    })
}

fn build_identity() -> String {
    let exe = std::env::current_exe()
        .ok()
        .and_then(|p| std::fs::metadata(p).ok())
        .map(|md| {
            let mtime = md
                .modified()
                .ok()
                .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
                .map(|d| d.as_secs())
                .unwrap_or(0);
            format!("{}/{mtime}", md.len())
        })
        .unwrap_or_default();
    format!("{}/{exe}", env!("CARGO_PKG_VERSION"))
}

/// FR-78 P2 — driver-facing environment that changes what the drivers
/// answer without changing anything the `MESHHARBORD_*` knobs or the hardware
/// fingerprint see. Measured on jupiter: RADV lists no video extensions
/// without `RADV_PERFTEST=video_encode` and three with it, and a restart that
/// added the flag replayed the cached no-Vulkan answer until the cache was
/// cleared by hand. The Vulkan loader's ICD selection and libva's driver
/// name / path are the same class of input.
const DRIVER_ENV: &[&str] = &[
    "RADV_PERFTEST",
    "RADV_DEBUG",
    "ANV_DEBUG",
    "MESA_LOADER_DRIVER_OVERRIDE",
    "VK_ICD_FILENAMES",
    "VK_DRIVER_FILES",
    "VK_LOADER_DRIVERS_SELECT",
    "VK_LOADER_DRIVERS_DISABLE",
    "LIBVA_DRIVER_NAME",
    "LIBVA_DRIVERS_PATH",
    "CUDA_VISIBLE_DEVICES",
];

/// Every `MESHHARBORD_*` knob the probe child could read, env AND config
/// fallbacks (the child receives both as real env), plus the driver-facing
/// variables in [`DRIVER_ENV`], hashed.
fn knobs_hash() -> String {
    let mut knobs: std::collections::BTreeMap<String, String> = std::collections::BTreeMap::new();
    for (name, value) in tunnel_core::env::config_fallbacks_for_child() {
        knobs.insert(name, value);
    }
    for (name, value) in std::env::vars_os() {
        let name = name.to_string_lossy();
        if knob_selected(&name) {
            knobs.insert(name.into_owned(), value.to_string_lossy().into_owned());
        }
    }
    hash_knobs(&knobs)
}

/// Which environment variables are part of the key: every `MESHHARBORD_*`
/// knob and the driver-facing names in [`DRIVER_ENV`].
fn knob_selected(name: &str) -> bool {
    name.starts_with("MESHHARBORD_") || DRIVER_ENV.contains(&name)
}

fn hash_knobs(knobs: &std::collections::BTreeMap<String, String>) -> String {
    let mut h = Sha256::new();
    for (k, v) in knobs {
        h.update(k.as_bytes());
        h.update(b"=");
        h.update(v.as_bytes());
        h.update(b"\n");
    }
    hex(&h.finalize())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub(crate) fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Read the file and accept it only under `key`, fresh enough.
pub(crate) fn load_matching(path: &Path, key: &CacheKey, now_unix: u64) -> Result<CacheFile, Miss> {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Err(Miss::NoFile),
        Err(e) => return Err(Miss::Unreadable(e.to_string())),
    };
    let file: CacheFile =
        serde_json::from_str(&text).map_err(|e| Miss::Unreadable(e.to_string()))?;
    if file.version != FORMAT_VERSION {
        return Err(Miss::FormatVersion(file.version));
    }
    if file.key.build != key.build {
        return Err(Miss::Build);
    }
    if file.key.hardware != key.hardware {
        return Err(Miss::Hardware);
    }
    if file.key.knobs != key.knobs {
        return Err(Miss::Knobs);
    }
    // A clock that went backwards reads as age 0: the key still gates.
    let age_secs = now_unix.saturating_sub(file.probed_at_unix);
    if age_secs > MAX_AGE_SECS {
        return Err(Miss::Stale { age_secs });
    }
    Ok(file)
}

/// Atomic: write a sibling temp file, then rename over the target, so a crash
/// mid-write leaves the previous cache (or none) rather than half a file.
pub(crate) fn store(path: &Path, file: &CacheFile) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let json = serde_json::to_vec_pretty(file).map_err(std::io::Error::other)?;
    let tmp = path.with_extension(format!("json.{}.tmp", std::process::id()));
    std::fs::write(&tmp, json)?;
    if let Err(e) = std::fs::rename(&tmp, path) {
        let _ = std::fs::remove_file(&tmp);
        return Err(e);
    }
    Ok(())
}

/// A result worth remembering: at least one hardware cell opened. See the
/// module doc for why a no-hardware answer is never cached.
pub(crate) fn worth_caching(caps: &AgentCaps) -> bool {
    caps.video_cells.iter().any(|c| c.hw)
}

#[cfg(test)]
mod tests {
    use super::*;
    use meshharbor_remote_control::models::{ChromaFormat, VideoBackend, VideoCell, VideoCodec};

    /// FR-78 P2 — the driver-facing variables are part of the key: a
    /// `RADV_PERFTEST` edit re-probes, an unrelated variable does not.
    #[test]
    fn driver_env_is_part_of_the_key() {
        assert!(knob_selected("MESHHARBORD_ENCODER_CELLS_DENY"));
        assert!(knob_selected("RADV_PERFTEST"));
        assert!(knob_selected("LIBVA_DRIVERS_PATH"));
        assert!(knob_selected("VK_ICD_FILENAMES"));
        assert!(!knob_selected("PATH"));
        assert!(!knob_selected("HOME"));
        let mut a = std::collections::BTreeMap::new();
        a.insert("MESHHARBORD_X".to_string(), "1".to_string());
        let mut b = a.clone();
        b.insert("RADV_PERFTEST".to_string(), "video_encode".to_string());
        assert_ne!(hash_knobs(&a), hash_knobs(&b));
    }

    fn key() -> CacheKey {
        CacheKey {
            build: "0.4.84/123/456".into(),
            hardware: "windows;os=26100.1;hw=NVIDIA|32.0.15.7247|PCI\\VEN_10DE".into(),
            knobs: "abc".into(),
        }
    }

    fn hw_caps() -> AgentCaps {
        AgentCaps {
            hw_encoders: vec!["ffmpeg-hevc_nvenc".into()],
            codecs: vec!["h265".into()],
            transports: vec!["data-channel-hevc".into()],
            video_cells: vec![VideoCell::new(
                VideoCodec::Hevc,
                VideoBackend::Nvenc,
                &[ChromaFormat::Yuv420, ChromaFormat::Yuv444],
                true,
            )],
            ..AgentCaps::default()
        }
    }

    fn tmp_path(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("meshharbor-caps-cache-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir.join(FILE_NAME)
    }

    #[test]
    fn store_then_load_round_trips_under_the_same_key() {
        let path = tmp_path("rt");
        let file = CacheFile::new(key(), 1_000, 3986, hw_caps(), Some((true, false)));
        store(&path, &file).unwrap();
        let back = load_matching(&path, &key(), 1_000 + 60).expect("hit");
        assert_eq!(back.probe_ms, 3986);
        assert_eq!(back.vp9_qsv_idr, Some((true, false)));
        assert_eq!(back.caps.video_cells, hw_caps().video_cells);
        assert!(
            !path.with_extension("json.tmp").exists(),
            "no temp file left behind"
        );
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn every_key_part_gates_and_age_gates() {
        let path = tmp_path("gates");
        store(&path, &CacheFile::new(key(), 1_000, 1, hw_caps(), None)).unwrap();
        let mut k = key();
        k.build = "0.4.85/1/1".into();
        assert_eq!(load_matching(&path, &k, 1_001).unwrap_err(), Miss::Build);
        let mut k = key();
        k.hardware = "windows;os=26100.2;hw=x".into();
        assert_eq!(load_matching(&path, &k, 1_001).unwrap_err(), Miss::Hardware);
        let mut k = key();
        k.knobs = "def".into();
        assert_eq!(load_matching(&path, &k, 1_001).unwrap_err(), Miss::Knobs);
        assert_eq!(
            load_matching(&path, &key(), 1_000 + MAX_AGE_SECS + 1).unwrap_err(),
            Miss::Stale {
                age_secs: MAX_AGE_SECS + 1
            }
        );
        assert!(load_matching(&path, &key(), 1_000 + MAX_AGE_SECS).is_ok());
        // A clock that went backwards is not stale.
        assert!(load_matching(&path, &key(), 10).is_ok());
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    #[test]
    fn a_missing_garbled_or_older_format_file_is_a_miss_not_an_error() {
        let path = tmp_path("miss");
        assert_eq!(load_matching(&path, &key(), 1).unwrap_err(), Miss::NoFile);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"{not json").unwrap();
        assert!(matches!(
            load_matching(&path, &key(), 1).unwrap_err(),
            Miss::Unreadable(_)
        ));
        let mut file = CacheFile::new(key(), 1, 1, hw_caps(), None);
        file.version = 0;
        std::fs::write(&path, serde_json::to_vec(&file).unwrap()).unwrap();
        assert_eq!(
            load_matching(&path, &key(), 1).unwrap_err(),
            Miss::FormatVersion(0)
        );
        let _ = std::fs::remove_dir_all(path.parent().unwrap());
    }

    /// The boot-time driver race: a probe that found NO hardware is the cheap
    /// case and the suspicious one, and must never be frozen for a week.
    #[test]
    fn only_a_result_with_a_hardware_cell_is_worth_caching() {
        assert!(worth_caching(&hw_caps()));
        let sw_only = AgentCaps {
            video_cells: vec![VideoCell::new(
                VideoCodec::H264,
                VideoBackend::Openh264,
                &[ChromaFormat::Yuv420],
                false,
            )],
            ..AgentCaps::default()
        };
        assert!(!worth_caching(&sw_only));
        assert!(!worth_caching(&AgentCaps::default()));
    }

    #[test]
    fn the_knob_hash_is_order_independent_and_value_sensitive() {
        let mut a = std::collections::BTreeMap::new();
        a.insert("MESHHARBORD_DC_H264".to_string(), "0".to_string());
        a.insert(
            "MESHHARBORD_ENCODER_CELLS_DENY".to_string(),
            "none".to_string(),
        );
        let mut b = std::collections::BTreeMap::new();
        b.insert(
            "MESHHARBORD_ENCODER_CELLS_DENY".to_string(),
            "none".to_string(),
        );
        b.insert("MESHHARBORD_DC_H264".to_string(), "0".to_string());
        assert_eq!(hash_knobs(&a), hash_knobs(&b));
        b.insert("MESHHARBORD_DC_H264".to_string(), "1".to_string());
        assert_ne!(hash_knobs(&a), hash_knobs(&b));
        assert_eq!(hash_knobs(&a).len(), 64);
    }

    #[test]
    fn the_kill_switch_reads_the_usual_spellings() {
        use tunnel_core::env::test_env::Saved;
        let _saved = Saved::cleared("CAPS_CACHE");
        assert!(enabled(), "default on");
        for off in ["0", "false", "OFF", "no"] {
            unsafe { tunnel_core::env::test_env::set("CAPS_CACHE", off) };
            assert!(!enabled(), "{off} must disable");
        }
        unsafe { tunnel_core::env::test_env::set("CAPS_CACHE", "1") };
        assert!(enabled());
    }
}
