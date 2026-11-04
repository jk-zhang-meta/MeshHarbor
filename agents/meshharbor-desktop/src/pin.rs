// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! #2286 — the "Being viewed" banner pinned to the top of the screen on a
//! Wayland desktop, where a client cannot place its own window.
//!
//! `panels::position_top_centre` asks for the top centre. X11 grants that,
//! and Wayland ignores it: GNOME and KDE both centred the banner, for the
//! whole session, over the middle of the screen the controller is working in
//! (and on Linux the banner is in the captured stream too). Each desktop gets
//! the one placement it allows a client:
//!
//! - **KDE Plasma** — a KWin script, loaded into the running KWin over D-Bus
//!   (`org.kde.kwin.Scripting`), puts the banner (found by its title) at the
//!   top centre of its screen and keeps it above. Nothing is written to the
//!   person's KWin configuration, and the script goes when that KWin does.
//! - **GNOME** — mutter offers no placement, no layer-shell and no scripting,
//!   so the companion runs under Xwayland there ([`prefer_x11`]). An X11
//!   window places itself and keeps itself above. Its pointer, though, is
//!   known only over X11 windows, so the banner stays pinned rather than
//!   tucking itself away ([`under_xwayland`]): GNOME's top bar is not one,
//!   and the top-edge gesture that brings it back would never be seen.
//!
//! `MESHHARBOR_DESKTOP_BANNER_PIN=0` turns both off.

use std::sync::atomic::{AtomicBool, Ordering};

/// The KWin script's name in KWin, the handle a reload replaces.
const SCRIPT_NAME: &str = "meshharbor-banner-pin";

/// `MESHHARBOR_DESKTOP_BANNER_PIN=0` (or `false`/`off`) — neither pin.
fn enabled() -> bool {
    !matches!(
        std::env::var("MESHHARBOR_DESKTOP_BANNER_PIN").ok().as_deref(),
        Some("0") | Some("false") | Some("off")
    )
}

/// `XDG_CURRENT_DESKTOP` is a colon-separated list (`ubuntu:GNOME`).
fn desktop_is(current: Option<&str>, name: &str) -> bool {
    current.is_some_and(|d| d.split(':').any(|p| p.eq_ignore_ascii_case(name)))
}

fn is_wayland(env: &impl Fn(&str) -> Option<String>) -> bool {
    env("XDG_SESSION_TYPE").as_deref() == Some("wayland") || env("WAYLAND_DISPLAY").is_some()
}

/// GNOME on Wayland, with an X display to reach (Xwayland), and no backend
/// already chosen by whoever started us.
fn wants_x11(env: impl Fn(&str) -> Option<String>) -> bool {
    is_wayland(&env)
        && desktop_is(env("XDG_CURRENT_DESKTOP").as_deref(), "GNOME")
        && env("DISPLAY").is_some_and(|d| !d.is_empty())
        && env("GDK_BACKEND").is_none()
}

/// Set once [`prefer_x11`] has moved this companion onto Xwayland.
static XWAYLAND: AtomicBool = AtomicBool::new(false);

/// GNOME: run the companion under Xwayland, so its banner can sit at the top.
///
/// ⚠️ Called FIRST in `main`: GTK reads `GDK_BACKEND` when it starts, and an
/// environment variable may only be set while no other thread exists.
pub fn prefer_x11() {
    if enabled() && wants_x11(|k| std::env::var(k).ok()) {
        // SAFETY: `main`'s first statement; no thread has been started yet.
        unsafe { std::env::set_var("GDK_BACKEND", "x11") };
        XWAYLAND.store(true, Ordering::SeqCst);
    }
}

/// This companion runs under Xwayland on a Wayland desktop ([`prefer_x11`]).
/// Its windows then see the pointer only while it is over an X11 window, so
/// the banner's reveal watch must not trust it (`panels::Sample::read`).
pub fn under_xwayland() -> bool {
    XWAYLAND.load(Ordering::SeqCst)
}

/// The KWin script: the banner, by its title, at the top centre of the
/// screen it is on, above every other window and out of the task switchers.
/// Placed again whenever it maps (a hidden banner comes back as a new
/// window) or its title changes; Plasma 5's names as a fallback.
fn kwin_script(title: &str) -> String {
    let title = serde_json::to_string(title).unwrap_or_else(|_| "\"\"".into());
    format!(
        r#"// MeshHarbor: the "Being viewed" banner pinned to the top (#2286).
const TITLE = {title};
function place(w) {{
    if (!w || w.caption !== TITLE) return;
    w.keepAbove = true;
    w.skipTaskbar = true;
    w.skipPager = true;
    w.skipSwitcher = true;
    const area = workspace.clientArea(KWin.FullScreenArea, w);
    const g = w.frameGeometry;
    w.frameGeometry = {{
        x: Math.round(area.x + (area.width - g.width) / 2),
        y: area.y + 48,
        width: g.width,
        height: g.height,
    }};
}}
function watch(w) {{
    place(w);
    if (w && w.captionChanged) w.captionChanged.connect(function () {{ place(w); }});
}}
(workspace.windowAdded || workspace.clientAdded).connect(watch);
(workspace.windowList ? workspace.windowList() : workspace.clientList()).forEach(watch);
"#
    )
}

/// Whether this process has loaded its own script yet: the first load
/// replaces whatever an older companion left in this KWin.
static LOADED_OURS: AtomicBool = AtomicBool::new(false);

/// KDE: load the pin script into the running KWin, unless this companion's
/// copy is there already. Blocking D-Bus, so call it off the UI thread and
/// off the async runtime. Failures are logged and leave the banner where
/// KWin puts it, as before #2286.
pub fn ensure_kwin_pin(title: &'static str) {
    let env = |k: &str| std::env::var(k).ok();
    if !enabled() || !is_wayland(&env) || !desktop_is(env("XDG_CURRENT_DESKTOP").as_deref(), "KDE")
    {
        return;
    }
    if let Err(e) = load_kwin_script(title) {
        tracing::warn!(error = %e, "could not pin the banner to the top through KWin (#2286)");
    }
}

fn load_kwin_script(title: &str) -> anyhow::Result<()> {
    use gio::glib::ToVariant;

    let conn = gio::bus_get_sync(gio::BusType::Session, gio::Cancellable::NONE)?;
    let call = |method: &str, args: Option<gio::glib::Variant>| {
        conn.call_sync(
            Some("org.kde.KWin"),
            "/Scripting",
            "org.kde.kwin.Scripting",
            method,
            args.as_ref(),
            None,
            gio::DBusCallFlags::NONE,
            3000,
            gio::Cancellable::NONE,
        )
    };
    let ours = LOADED_OURS.load(Ordering::SeqCst);
    let loaded = call("isScriptLoaded", Some((SCRIPT_NAME,).to_variant()))?
        .get::<(bool,)>()
        .is_some_and(|(b,)| b);
    if ours && loaded {
        return Ok(());
    }
    if loaded {
        // An older companion's copy: this one's title or placement may differ.
        call("unloadScript", Some((SCRIPT_NAME,).to_variant()))?;
    }
    let dir = std::env::var_os("XDG_RUNTIME_DIR")
        .map(std::path::PathBuf::from)
        .ok_or_else(|| anyhow::anyhow!("no XDG_RUNTIME_DIR"))?
        .join("meshharbor-desktop");
    std::fs::create_dir_all(&dir)?;
    let path = dir.join("banner-pin.js");
    std::fs::write(&path, kwin_script(title))?;
    let path = path
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("the script's path is not UTF-8"))?
        .to_owned();
    call("loadScript", Some((path, SCRIPT_NAME).to_variant()))?;
    call("start", None)?;
    LOADED_OURS.store(true, Ordering::SeqCst);
    tracing::info!("the banner is pinned to the top of the screen by a KWin script (#2286)");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn env(pairs: &'static [(&'static str, &'static str)]) -> impl Fn(&str) -> Option<String> {
        move |k| {
            pairs
                .iter()
                .find(|(n, _)| *n == k)
                .map(|(_, v)| (*v).to_string())
        }
    }

    /// Xwayland only for GNOME on Wayland with an X display, and never over
    /// a backend someone already chose.
    #[test]
    fn only_gnome_on_wayland_with_an_x_display_takes_xwayland() {
        assert!(wants_x11(env(&[
            ("XDG_SESSION_TYPE", "wayland"),
            ("XDG_CURRENT_DESKTOP", "ubuntu:GNOME"),
            ("DISPLAY", ":0"),
        ])));
        assert!(
            !wants_x11(env(&[
                ("XDG_SESSION_TYPE", "wayland"),
                ("XDG_CURRENT_DESKTOP", "KDE"),
                ("DISPLAY", ":0"),
            ])),
            "KDE pins through KWin and stays native"
        );
        assert!(
            !wants_x11(env(&[
                ("XDG_SESSION_TYPE", "wayland"),
                ("XDG_CURRENT_DESKTOP", "GNOME"),
            ])),
            "no Xwayland to reach"
        );
        assert!(
            !wants_x11(env(&[
                ("XDG_SESSION_TYPE", "x11"),
                ("XDG_CURRENT_DESKTOP", "GNOME"),
                ("DISPLAY", ":0"),
            ])),
            "already X11"
        );
        assert!(
            !wants_x11(env(&[
                ("XDG_SESSION_TYPE", "wayland"),
                ("XDG_CURRENT_DESKTOP", "GNOME"),
                ("DISPLAY", ":0"),
                ("GDK_BACKEND", "wayland"),
            ])),
            "someone chose the backend"
        );
    }

    /// The script matches the banner by its exact title, written as a JS
    /// string, and keeps it above.
    #[test]
    fn the_kwin_script_names_the_banner_by_its_title() {
        let s = kwin_script("MeshHarbor — session active");
        assert!(
            s.contains(r#"const TITLE = "MeshHarbor — session active";"#),
            "{s}"
        );
        assert!(s.contains("w.keepAbove = true;"));
        assert!(s.contains("y: area.y + 48"));
        let tricky = kwin_script("a\"b\\c");
        assert!(
            tricky.contains(r#"const TITLE = "a\"b\\c";"#),
            "escaped: {tricky}"
        );
    }
}
