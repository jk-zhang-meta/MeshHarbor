// SPDX-License-Identifier: AGPL-3.0-only
// Copyright (C) 2026 G ROX EOOD
//! FR-102 P3 — the install trace's fetch counters (spec §3e item 2,
//! `docs/growth-observability.md`).
//!
//! Every request for an installer, a release manifest or a served install
//! script carries a User-Agent that says what kind of client asked: the
//! wizard (`meshharbor-setup/…`), `curl`/`wget` (`install.sh`), PowerShell
//! (`install.ps1`), a browser, or something else. [`classify_user_agent`]
//! turns that into one of five **classes**, and [`count_fetch`] adds one to
//! the `growth_daily` counter `{asset, client, os}` for the UTC day — a
//! number, never the User-Agent and never the address.
//!
//! ⚠️ **The updater is never counted.** `meshharbord/<ver>` is the daemon's own
//! update check, and by default it asks `meshharbor.itachi.fans` from self-hosted
//! devices as well (`agents/meshharbord/src/updater.rs`, `DEFAULT_PROXY_URL`).
//! Counting it would be exactly the self-host telemetry the product promises
//! not to collect (`LICENSING.md`, `docs/business-model.md` §6). So is every
//! other identity of our own — `meshharbord-*`, `meshharbor-cli/`, the pre-rename
//! updater's spelling, any product token of ours that is not the wizard:
//! [`UaClass::Updater`], whose [`UaClass::counted`] is `None`, and a fetch
//! with it writes nothing.
//!
//! The write is spawned and best-effort: an install script must be served
//! at wire speed whatever the database is doing, and a lost increment is a
//! lost increment. `growth.install_counters = false` switches it off.
//!
//! **P3c — the lab is not a market.** A fetch carries no tenant, so the
//! exclusion set cannot remove the lab's own installs; the operator names
//! the internal source networks instead (`growth.internal_networks`). A
//! counted fetch whose client address falls inside is counted under the
//! client class [`INTERNAL_CLIENT`] instead of its own, so the classes stop
//! inflating and the digest still says how many were left out. The address
//! comes from [`meshharbor_core::client_ip`] — the per-IP limiter's rule, the
//! only one the server has — is compared in memory, and is dropped: the
//! row stays three enum-like dimensions and a count. The updater rule comes
//! first: a `meshharbord/` fetch from the lab is still never counted at all.

use std::{collections::BTreeMap, net::SocketAddr};

use axum::http::{HeaderMap, header::USER_AGENT};
use meshharbor_services::dao::growth::GrowthDao;

use crate::FleetState;

/// `growth_daily.source` for every counter here, and the `metric` of a
/// fetch — spelled in the core DAO, which the host's digest reads them by.
pub use meshharbor_services::dao::growth::{
    INSTALL_FETCH_METRIC as METRIC_FETCH, INSTALL_INTERNAL_CLIENT as INTERNAL_CLIENT,
    INSTALL_SOURCE as SOURCE,
};

/// The `asset` dimension's spellings — a grouping key in the digest, so a
/// rename splits the series.
pub mod asset {
    /// `GET /api/agent/latest-release`.
    pub const AGENT_LATEST_RELEASE: &str = "agent-latest-release";
    /// `GET /api/setup/latest-release`.
    pub const SETUP_LATEST_RELEASE: &str = "setup-latest-release";
    /// `GET /api/setup/install.sh`.
    pub const INSTALL_SH: &str = "install.sh";
    /// `GET /api/setup/install.ps1`.
    pub const INSTALL_PS1: &str = "install.ps1";

    /// `GET /api/agent/installer/{flavour}` — `installer-peruser` /
    /// `installer-permachine` (the normalised flavour).
    pub fn installer(flavour: &str) -> String {
        format!("installer-{flavour}")
    }

    /// `GET /api/setup/{platform}` — the wizard archive itself:
    /// `setup-windows-x86_64` / `setup-linux-x86_64` / `setup-macos`.
    pub fn setup(platform: &str) -> String {
        format!("setup-{platform}")
    }
}

/// What kind of client fetched. The five counted classes are the digest's
/// vocabulary; `Updater` is the one that is never written.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UaClass {
    /// `meshharbor-setup/<ver>` — the wizard, in-process.
    Wizard,
    /// `curl/…` or `Wget/…` — `install.sh`, or a person at a terminal.
    ScriptSh,
    /// Windows PowerShell 5.1 or pwsh 7 (`Invoke-WebRequest`,
    /// `Invoke-RestMethod`) — `install.ps1`, or a person at a prompt.
    ScriptPs1,
    /// A browser (`Mozilla/…` that is not PowerShell).
    Browser,
    /// Anything else, a missing header included.
    Other,
    /// The daemon or the CLI, in any version and any subsystem. **Never
    /// counted** — see the module docs.
    Updater,
}

impl UaClass {
    /// The `client` dimension value, or `None` for the class that must not
    /// be counted.
    pub fn counted(self) -> Option<&'static str> {
        match self {
            UaClass::Wizard => Some("wizard"),
            UaClass::ScriptSh => Some("script-sh"),
            UaClass::ScriptPs1 => Some("script-ps1"),
            UaClass::Browser => Some("browser"),
            UaClass::Other => Some("other"),
            UaClass::Updater => None,
        }
    }
}

/// The one product token that is counted. Every OTHER product token of ours
/// — `meshharbord/`, `meshharbord-exec-service/`, `meshharbord-anchor/`,
/// `meshharbord-localapi/`, `meshharbord-ssh-service/`, `meshharbord-crash-reporter/`,
/// `meshharbor-cli/`, `meshharbor-token-renewal/`, the updater's pre-rename
/// spelling, and whatever a later release adds — is the product's own
/// machinery and is never counted. Decided by the common prefix, not by a
/// list, so a new identity of ours is excluded before anyone remembers to
/// name it here.
const WIZARD_PREFIX: &str = "meshharbor-setup/";
const OWN_PREFIX: &str = "meshharbor";

/// Pure: the class of a User-Agent value (`None` = no header).
pub fn classify_user_agent(ua: Option<&str>) -> UaClass {
    let ua = ua.map(str::trim).unwrap_or("");
    if ua.starts_with(WIZARD_PREFIX) {
        return UaClass::Wizard;
    }
    if ua.starts_with(OWN_PREFIX) {
        return UaClass::Updater;
    }
    let lower = ua.to_ascii_lowercase();
    if lower.starts_with("curl/") || lower.starts_with("wget/") {
        return UaClass::ScriptSh;
    }
    // Both shells send a `Mozilla/5.0 (…) WindowsPowerShell/5.1…` or
    // `… PowerShell/7…` UA, so this must be decided before the browser rule.
    if lower.contains("powershell") {
        return UaClass::ScriptPs1;
    }
    if lower.starts_with("mozilla/") {
        return UaClass::Browser;
    }
    UaClass::Other
}

/// Pure: the OS a User-Agent hints at — `windows`, `macos`, `linux` or
/// `unknown`. `curl` says nothing about its host, so a script fetch is
/// usually `unknown` here; the asset decides first ([`os_dimension`]).
pub fn os_hint(ua: Option<&str>) -> &'static str {
    let lower = ua.map(str::trim).unwrap_or("").to_ascii_lowercase();
    if lower.contains("windows") {
        "windows"
    } else if lower.contains("macintosh") || lower.contains("mac os x") || lower.contains("darwin")
    {
        "macos"
    } else if lower.contains("linux") || lower.contains("x11;") {
        "linux"
    } else {
        "unknown"
    }
}

/// Pure: the `os` dimension of a fetch — what the asset itself implies (an
/// MSI, `install.ps1` and the Windows wizard are Windows; the Linux and
/// macOS wizard archives name their OS), else the User-Agent's hint.
pub fn os_dimension(asset: &str, ua: Option<&str>) -> &'static str {
    if asset.starts_with("installer-")
        || asset == asset::INSTALL_PS1
        || asset.starts_with("setup-windows")
    {
        "windows"
    } else if asset.starts_with("setup-macos") {
        "macos"
    } else if asset.starts_with("setup-linux") {
        "linux"
    } else {
        os_hint(ua)
    }
}

/// Pure: the dimensions one fetch counts under, or `None` when it must not
/// be counted at all. What a test asserts and what [`count_fetch`] writes.
/// `internal` (P3c) — the client address fell inside one of the operator's
/// internal networks — replaces the class with [`INTERNAL_CLIENT`]; it never
/// makes an uncounted fetch counted.
pub fn fetch_dims(
    asset: &str,
    ua: Option<&str>,
    internal: bool,
) -> Option<BTreeMap<String, String>> {
    let class = classify_user_agent(ua).counted()?;
    let client = if internal { INTERNAL_CLIENT } else { class };
    let mut dims = BTreeMap::new();
    dims.insert("asset".to_string(), asset.to_string());
    dims.insert("client".to_string(), client.to_string());
    dims.insert("os".to_string(), os_dimension(asset, ua).to_string());
    Some(dims)
}

/// Today, UTC, as the `growth_daily` day key.
fn today_utc() -> String {
    chrono::Utc::now().format("%Y-%m-%d").to_string()
}

/// Count one fetch of `asset` by the client `headers` describe. Reads the
/// User-Agent and — only to test it against the internal networks, then
/// dropped — the client address (`peer` is the socket peer the listener
/// recorded, the fallback of the limiter's rule); spawns the write.
pub fn count_fetch(state: &FleetState, headers: &HeaderMap, peer: Option<SocketAddr>, asset: &str) {
    if !state.settings.growth.install_counters {
        return;
    }
    let ua = headers.get(USER_AGENT).and_then(|v| v.to_str().ok());
    // P3c — one rule for "the client's address": the limiter's. Compared in
    // memory and dropped; skipped outright while no network is configured.
    let internal = !state.internal_networks.is_empty()
        && meshharbor_core::client_ip::client_ip_or_peer(
            headers,
            peer,
            state.settings.app.rate_limit_trusted_hops,
        )
        .is_some_and(|ip| state.internal_networks.contains(ip));
    let Some(dims) = fetch_dims(asset, ua, internal) else {
        return;
    };
    let day = today_utc();
    let db = state.db.clone();
    tokio::spawn(async move {
        if let Err(e) = GrowthDao::new(&db)
            .bump_daily(&day, SOURCE, METRIC_FETCH, &dims, 1)
            .await
        {
            tracing::debug!(error = %e, "install trace: fetch counter write failed");
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    const PS51: &str =
        "Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.19041.1";
    const PS7: &str =
        "Mozilla/5.0 (Windows NT 10.0; Microsoft Windows 10.0.22631; en-US) PowerShell/7.4.1";
    const CHROME_WIN: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36";
    const SAFARI_MAC: &str = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15";
    const FIREFOX_LINUX: &str =
        "Mozilla/5.0 (X11; Linux x86_64; rv:130.0) Gecko/20100101 Firefox/130.0";

    /// Every class, by the UA each real client sends.
    #[test]
    fn classifies_every_real_client() {
        assert_eq!(
            classify_user_agent(Some("meshharbor-setup/0.4.136")),
            UaClass::Wizard
        );
        assert_eq!(classify_user_agent(Some("curl/8.5.0")), UaClass::ScriptSh);
        assert_eq!(classify_user_agent(Some("Wget/1.21.4")), UaClass::ScriptSh);
        assert_eq!(classify_user_agent(Some("wget/1.14")), UaClass::ScriptSh);
        assert_eq!(classify_user_agent(Some(PS51)), UaClass::ScriptPs1);
        assert_eq!(classify_user_agent(Some(PS7)), UaClass::ScriptPs1);
        assert_eq!(classify_user_agent(Some(CHROME_WIN)), UaClass::Browser);
        assert_eq!(classify_user_agent(Some(SAFARI_MAC)), UaClass::Browser);
        assert_eq!(classify_user_agent(Some(FIREFOX_LINUX)), UaClass::Browser);
        assert_eq!(
            classify_user_agent(Some("python-requests/2.32.3")),
            UaClass::Other
        );
        assert_eq!(
            classify_user_agent(Some("Go-http-client/1.1")),
            UaClass::Other
        );
        assert_eq!(classify_user_agent(Some("")), UaClass::Other);
        assert_eq!(classify_user_agent(None), UaClass::Other);
    }

    /// The rule the product promises: the daemon's own fetches — the updater
    /// first of all, every subsystem that shares its name, and any product
    /// token of ours that is not the wizard (the pre-rename updater's
    /// spelling and a future identity alike) — and the CLI's, are never
    /// counted.
    #[test]
    fn the_updater_and_every_daemon_identity_are_never_counted() {
        for ua in [
            "meshharbord/0.4.135",
            "meshharbord/0.3.0-rc.480",
            "meshharbord-exec-service/0.4.135",
            "meshharbord-anchor/0.4.135",
            "meshharbord-localapi/0.4.135",
            "meshharbord-ssh-service/0.4.135",
            "meshharbord-crash-reporter/0.4.135",
            "meshharbor-cli/0.4.135",
            "meshharbor-token-renewal/0.4.135",
            "meshharbor-something-from-a-later-release/0.5.0",
        ] {
            assert_eq!(classify_user_agent(Some(ua)), UaClass::Updater, "{ua}");
            assert_eq!(UaClass::Updater.counted(), None);
            assert_eq!(
                fetch_dims(asset::AGENT_LATEST_RELEASE, Some(ua), false),
                None,
                "{ua} must write nothing"
            );
            // P3c — from the lab too: `internal` never makes the updater
            // counted.
            assert_eq!(
                fetch_dims(asset::AGENT_LATEST_RELEASE, Some(ua), true),
                None,
                "{ua} must write nothing from an internal network either"
            );
        }
        // Only the daemon's names: a browser whose UA merely mentions the
        // word is not the updater, and the wizard is its own class.
        assert_eq!(
            classify_user_agent(Some("Mozilla/5.0 (X11; Linux) meshharbord-docs-reader")),
            UaClass::Browser
        );
        assert_eq!(
            classify_user_agent(Some("meshharbor-setup/0.4.136")).counted(),
            Some("wizard")
        );
    }

    /// Each counted class has its dimension value, and the five spellings
    /// are the digest's grouping keys.
    #[test]
    fn counted_spellings_are_locked() {
        assert_eq!(UaClass::Wizard.counted(), Some("wizard"));
        assert_eq!(UaClass::ScriptSh.counted(), Some("script-sh"));
        assert_eq!(UaClass::ScriptPs1.counted(), Some("script-ps1"));
        assert_eq!(UaClass::Browser.counted(), Some("browser"));
        assert_eq!(UaClass::Other.counted(), Some("other"));
    }

    /// The asset decides the OS where it can; the UA fills in for the rest;
    /// a curl fetch of `install.sh` is honestly `unknown`.
    #[test]
    fn the_os_dimension_follows_the_asset_then_the_user_agent() {
        assert_eq!(
            os_dimension("installer-permachine", Some("curl/8")),
            "windows"
        );
        assert_eq!(os_dimension(asset::INSTALL_PS1, None), "windows");
        assert_eq!(
            os_dimension("setup-windows-x86_64", Some(SAFARI_MAC)),
            "windows"
        );
        assert_eq!(os_dimension("setup-macos", Some(CHROME_WIN)), "macos");
        assert_eq!(os_dimension("setup-linux-x86_64", None), "linux");
        assert_eq!(
            os_dimension(asset::INSTALL_SH, Some("curl/8.5.0")),
            "unknown"
        );
        assert_eq!(os_dimension(asset::INSTALL_SH, Some(SAFARI_MAC)), "macos");
        assert_eq!(
            os_dimension(asset::AGENT_LATEST_RELEASE, Some(FIREFOX_LINUX)),
            "linux"
        );
        assert_eq!(
            os_dimension(asset::AGENT_LATEST_RELEASE, Some(PS7)),
            "windows"
        );
        assert_eq!(
            os_hint(Some(
                "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)"
            )),
            "macos"
        );
        assert_eq!(os_hint(Some("Mozilla/5.0 (Linux; Android 14)")), "linux");
        assert_eq!(os_hint(None), "unknown");
    }

    /// The whole dimension set for the fetches the field actually makes.
    #[test]
    fn fetch_dims_for_the_real_paths() {
        let dims = |asset: &str, ua: &str| {
            let d = fetch_dims(asset, Some(ua), false).expect("counted");
            (d["asset"].clone(), d["client"].clone(), d["os"].clone())
        };
        // The wizard resolving and downloading the perMachine MSI.
        assert_eq!(
            dims(&asset::installer("permachine"), "meshharbor-setup/0.4.136"),
            (
                "installer-permachine".into(),
                "wizard".into(),
                "windows".into()
            )
        );
        // install.sh: the manifest, then (on Linux) nothing else through us.
        assert_eq!(
            dims(asset::AGENT_LATEST_RELEASE, "curl/8.5.0"),
            (
                "agent-latest-release".into(),
                "script-sh".into(),
                "unknown".into()
            )
        );
        // install.ps1: the script, the manifest and the MSI, all PowerShell.
        assert_eq!(
            dims(asset::INSTALL_PS1, PS51),
            ("install.ps1".into(), "script-ps1".into(), "windows".into())
        );
        assert_eq!(
            dims(&asset::installer("peruser"), PS7),
            (
                "installer-peruser".into(),
                "script-ps1".into(),
                "windows".into()
            )
        );
        // A person downloading the wizard from the site.
        assert_eq!(
            dims(&asset::setup("windows-x86_64"), CHROME_WIN),
            (
                "setup-windows-x86_64".into(),
                "browser".into(),
                "windows".into()
            )
        );
        // No header at all is still a fetch.
        let d = fetch_dims(asset::INSTALL_SH, None, false).unwrap();
        assert_eq!(d["client"], "other");
        assert_eq!(d["os"], "unknown");
        // And a row carries exactly these three keys — no UA, no address.
        assert_eq!(
            d.keys().cloned().collect::<Vec<_>>(),
            ["asset", "client", "os"]
        );
    }

    /// P3c — a fetch from an internal network keeps its asset and OS and
    /// trades its class for `internal`, whatever the class was; the row is
    /// still the same three keys, so nothing about the address reaches it.
    #[test]
    fn an_internal_fetch_is_counted_as_internal_instead_of_its_class() {
        for ua in [
            Some("curl/8.5.0"),
            Some(PS51),
            Some("meshharbor-setup/0.4.139"),
            Some(CHROME_WIN),
            None,
        ] {
            let d = fetch_dims(asset::INSTALL_PS1, ua, true).expect("counted");
            assert_eq!(d["client"], INTERNAL_CLIENT, "{ua:?}");
            assert_eq!(d["asset"], "install.ps1");
            assert_eq!(d["os"], "windows");
            assert_eq!(
                d.keys().cloned().collect::<Vec<_>>(),
                ["asset", "client", "os"]
            );
        }
        // The spelling is the digest's grouping key, and no class shares it.
        assert_eq!(INTERNAL_CLIENT, "internal");
        for class in [
            UaClass::Wizard,
            UaClass::ScriptSh,
            UaClass::ScriptPs1,
            UaClass::Browser,
            UaClass::Other,
        ] {
            assert_ne!(class.counted(), Some(INTERNAL_CLIENT));
        }
    }
}
