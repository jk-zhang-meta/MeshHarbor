// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-135 — every native HTTP client starts here, and connects WITHOUT a proxy.
//!
//! A proxy app in "system proxy" mode (Clash and the like) sets the OS proxy and
//! `HTTP(S)_PROXY` / `ALL_PROXY`. reqwest honours both by default, so before this the daemon,
//! `mh`, the companion, the wizard and the updater sent their traffic to the centre through the
//! proxy: the centre saw the proxy's exit address (the wrong country, so the wrong zone), every
//! call paid the detour, and a proxy rule could break the control plane. A TUN-mode VPN captures
//! packets below every application; it cannot be avoided and is not avoided here.
//!
//! [`builder`] is the one place a native `reqwest::Client` comes from. It calls `.no_proxy()`,
//! which turns off the environment variables AND the platform's system proxy (WinINET / the
//! macOS system configuration) in one switch. The source guard
//! (`crates/agent-core/tests/fr135_proxy_guard.rs`) fails when native code builds a client any
//! other way.
//!
//! The opt-in for a network that reaches the internet only through a proxy:
//!
//! - `use_system_proxy = true` in the device config — device-owned, never pushable by the server
//!   (absent from `DesiredConfig`). Read by every process that reads the device config: the
//!   config loader records the last value it parsed ([`note_config`]). The companion and `mh` read
//!   it once at start ([`read_device_opt_in`]) where they can read the file.
//! - `MESHHARBOR_USE_SYSTEM_PROXY=1` in the environment, for a process with no device config it can
//!   read (a tunnel-only host, the setup wizard, the companion of a machine-global install).
//!
//! Either one on, and [`builder`] is reqwest's default: the system and environment proxies.
//!
//! ⚠️ WebSocket, DERP and the overlay never had a proxy to skip: `tokio-tungstenite` and every raw
//! socket dial `TcpStream::connect` directly, so only HTTP needed this.

use std::sync::atomic::{AtomicBool, Ordering};

/// `MESHHARBOR_USE_SYSTEM_PROXY=1` (or `true` / `yes` / `on`): honour the proxies again.
pub const OPT_IN_ENV: &str = "MESHHARBOR_USE_SYSTEM_PROXY";

/// The device config's `use_system_proxy`, as last parsed by this process.
static CONFIG_OPT_IN: AtomicBool = AtomicBool::new(false);

/// The start of every native HTTP client: no proxy, unless the device opted in.
pub fn builder() -> reqwest::ClientBuilder {
    builder_with(use_system_proxy())
}

/// [`builder`] with the choice made by the caller (tests, and a caller that already knows).
/// Installs the FR-134 management-path resolver so every native HTTP request to the centre's
/// host follows the active/kept management path automatically while leaving all other hosts
/// direct.
pub fn builder_with(system_proxy: bool) -> reqwest::ClientBuilder {
    // fr-135: allowed — the helper itself.
    let builder = reqwest::Client::builder().dns_resolver(crate::management_path::resolver());
    if system_proxy {
        builder
    } else {
        builder.no_proxy()
    }
}

/// `reqwest::Client::new()`, through [`builder`]. Panics where `Client::new` does: when the TLS
/// backend cannot be initialised.
pub fn client() -> reqwest::Client {
    builder()
        .build()
        .expect("building the HTTP client (TLS backend)")
}

/// Whether proxies are honoured: the environment opt-in or the device config's.
pub fn use_system_proxy() -> bool {
    env_opt_in() || CONFIG_OPT_IN.load(Ordering::Relaxed)
}

fn parse_opt_in_value(raw: &str) -> bool {
    matches!(
        raw.trim().to_ascii_lowercase().as_str(),
        "1" | "true" | "yes" | "on"
    )
}

fn env_opt_in() -> bool {
    std::env::var(OPT_IN_ENV).is_ok_and(|v| parse_opt_in_value(&v))
}

/// The config loader parsed a device config: its `use_system_proxy` is this process's from now
/// on (the next client built follows it).
pub(crate) fn note_config(use_system_proxy: bool) {
    CONFIG_OPT_IN.store(use_system_proxy, Ordering::Relaxed);
}

/// For a process that does not otherwise load the device config before its first request (the
/// companion, `mh`, the setup wizard): read it where this user can, so its `use_system_proxy`
/// applies. The paths are tried in the order the binaries resolve them; one that is absent or
/// unreadable (the Windows machine-global file is SYSTEM + Administrators only; `/etc/meshharbor`
/// is root-only on Unix) is skipped silently, and the environment opt-in remains.
pub fn read_device_opt_in() {
    let mut paths = Vec::new();
    #[cfg(target_os = "windows")]
    paths.push(crate::config::machine_global_config_path());
    if let Ok(p) = crate::config::default_config_path() {
        paths.push(p);
    }
    #[cfg(target_os = "linux")]
    paths.push(crate::appdirs::system_config_path());
    #[cfg(target_os = "macos")]
    paths.push(std::path::PathBuf::from("/etc/meshharbor/config.toml"));
    for p in paths {
        if let Some(meta) = startup_meta_in(&p) {
            note_config(meta.use_system_proxy);
            crate::management_path::note_config(&meta.server_url, &meta.management_entries);
            return;
        }
    }
}

#[derive(Debug, Default, PartialEq, Eq, serde::Deserialize)]
struct StartupConfigMeta {
    #[serde(default)]
    use_system_proxy: bool,
    #[serde(default)]
    server_url: String,
    #[serde(default)]
    management_entries: Vec<String>,
}

/// Read the minimal startup keys (`use_system_proxy`, `server_url`, `management_entries`)
/// without running the full config loader (whose warnings belong to the daemon's own run).
/// `None` = absent, unreadable or not a config.
fn startup_meta_in(path: &std::path::Path) -> Option<StartupConfigMeta> {
    let raw = std::fs::read_to_string(path).ok()?;
    toml::from_str::<StartupConfigMeta>(&raw).ok()
}

/// The one key, read without the full loader. Kept as a thin helper for unit tests.
#[cfg(test)]
fn opt_in_in(path: &std::path::Path) -> Option<bool> {
    startup_meta_in(path).map(|c| c.use_system_proxy)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_opt_in_value_parser_accepts_truthy_forms_only() {
        for on in ["1", "true", "TRUE", " yes ", "On"] {
            assert!(parse_opt_in_value(on), "expected true for {on:?}");
        }
        for off in ["", "0", "false", "no", "off", "2", "proxy"] {
            assert!(!parse_opt_in_value(off), "expected false for {off:?}");
        }
    }

    #[test]
    fn opt_in_in_reads_key_defaults_false_and_skips_missing_or_invalid() {
        let dir = tempfile::tempdir().unwrap();
        let missing = dir.path().join("absent.toml");
        assert_eq!(opt_in_in(&missing), None);

        let enabled = dir.path().join("on.toml");
        std::fs::write(&enabled, "use_system_proxy = true\n").unwrap();
        assert_eq!(opt_in_in(&enabled), Some(true));

        let disabled = dir.path().join("off.toml");
        std::fs::write(&disabled, "use_system_proxy = false\n").unwrap();
        assert_eq!(opt_in_in(&disabled), Some(false));

        let omitted = dir.path().join("default.toml");
        std::fs::write(&omitted, "server_url = \"https://example.test\"\n").unwrap();
        assert_eq!(opt_in_in(&omitted), Some(false));

        let corrupt = dir.path().join("bad.toml");
        std::fs::write(&corrupt, "use_system_proxy = [not a bool\n").unwrap();
        assert_eq!(opt_in_in(&corrupt), None);
    }
}
