// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-135 — the companion's web views skip the system proxy, as its HTTP clients do
//! (`meshharbor_node_core::http_client`), unless the device opted in (`use_system_proxy`,
//! `MESHHARBOR_USE_SYSTEM_PROXY=1`).
//!
//! | Platform | Engine | How |
//! |---|---|---|
//! | Windows | WebView2 | `--no-proxy-server` through `WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS`, set before the first web view exists |
//! | Linux | WebKitGTK | the shared web context's proxy mode set to `NoProxy` from the main window, before any window loads the centre |
//! | macOS | WKWebView | not done: WebKit sets custom proxies (macOS 14+) and has no "direct" setting, so it follows the system proxy |
//!
//! ⚠️ Windows: every WebView2 in one process must be created with the SAME browser arguments, or
//! the second creation fails. Per-window `additional_browser_args` would have to be repeated on
//! every builder AND in `tauri.conf.json` (the main window), and the conf cannot follow the
//! opt-in; the environment variable applies to all of them at once.

/// wry's own WebView2 arguments, which an explicit value replaces (wry
/// `webview2/mod.rs`, `create_environment`): kept so the mini menu and SmartScreen stay off.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
const WRY_DEFAULT_ARGS: &str = "--disable-features=msWebOOUI,msPdfOOUI,msSmartScreenProtection";
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
const NO_PROXY_ARG: &str = "--no-proxy-server";
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
const WEBVIEW2_ARGS_ENV: &str = "WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS";

/// The WebView2 arguments with `--no-proxy-server` added to whatever the environment already
/// holds; `None` when they are already there.
#[cfg_attr(not(target_os = "windows"), allow(dead_code))]
fn webview2_args(existing: Option<&str>) -> Option<String> {
    let existing = existing.unwrap_or("").trim();
    if existing.split_whitespace().any(|a| a == NO_PROXY_ARG) {
        return None;
    }
    let mut args = String::from(WRY_DEFAULT_ARGS);
    if !existing.is_empty() {
        args.push(' ');
        args.push_str(existing);
    }
    args.push(' ');
    args.push_str(NO_PROXY_ARG);
    Some(args)
}

/// Windows: `main`'s first statements, before any thread or web view exists.
#[cfg(target_os = "windows")]
pub fn before_any_webview() {
    if meshharbor_node_core::http_client::use_system_proxy() {
        return;
    }
    let existing = std::env::var(WEBVIEW2_ARGS_ENV).ok();
    if let Some(args) = webview2_args(existing.as_deref()) {
        // SAFETY: called from `main` before any thread has been started.
        unsafe { std::env::set_var(WEBVIEW2_ARGS_ENV, args) };
    }
}

/// Linux: the web context every window shares (Tauri keys it by data directory, and no window
/// sets one) stops using the proxy. Called on the main window in `setup`, before any window
/// loads the centre.
#[cfg(target_os = "linux")]
pub fn on_main_window<R: tauri::Runtime>(window: &tauri::WebviewWindow<R>) {
    if meshharbor_node_core::http_client::use_system_proxy() {
        return;
    }
    let done = window.with_webview(|webview| {
        use webkit2gtk::{NetworkProxyMode, WebViewExt, WebsiteDataManagerExt};
        match webview.inner().website_data_manager() {
            Some(manager) => manager.set_network_proxy_settings(NetworkProxyMode::NoProxy, None),
            None => tracing::warn!("FR-135: the web view has no data manager; it may use a proxy"),
        }
    });
    if let Err(e) = done {
        tracing::warn!(%e, "FR-135: could not reach the web view; it may use a proxy");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_proxy_is_added_once_and_keeps_wry_defaults_and_existing_arguments() {
        assert_eq!(
            webview2_args(None).as_deref(),
            Some(
                "--disable-features=msWebOOUI,msPdfOOUI,msSmartScreenProtection --no-proxy-server"
            )
        );
        assert_eq!(
            webview2_args(Some("--lang=de")).as_deref(),
            Some(
                "--disable-features=msWebOOUI,msPdfOOUI,msSmartScreenProtection --lang=de \
                 --no-proxy-server"
            )
        );
        assert_eq!(webview2_args(Some("--x --no-proxy-server")), None);
    }
}
