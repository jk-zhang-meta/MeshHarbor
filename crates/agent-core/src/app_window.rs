// SPDX-License-Identifier: MPL-2.0
//! The desktop companion's viewer window on macOS and Linux: an APP WINDOW of
//! an installed Chromium-family browser (`--app=<url>`: no tab strip, no
//! address bar), so a remote-control session opens in a window of its own
//! rather than a browser tab.
//!
//! Windows shows the viewer in its own WebView2 window, which is Chromium. The
//! system webviews of the other two are WebKit. The viewer decodes its video
//! with WebCodecs over WebRTC (`VideoDecoder`, `RTCRtpScriptTransform`, VP9
//! 4:4:4 and HEVC) and has only ever been proven on Chromium; WebKitGTK keeps
//! WebRTC off unless the embedder turns on a setting it marks experimental.
//! So the viewer borrows the Chromium engine the machine already has.
//!
//! The decision (which browser, which command line) is pure and takes its
//! platform as an argument, so both platforms' rules are tested on any host.
//! It lives here, beside `rdp_client`, because the companion crate links the
//! system webview and cannot be built or tested on a host without it.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

/// The platforms that open the viewer this way.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Platform {
    MacOs,
    Linux,
}

impl Platform {
    /// This build's platform; `None` where the viewer has a window of the
    /// companion's own (Windows).
    pub const fn current() -> Option<Self> {
        if cfg!(target_os = "macos") {
            Some(Self::MacOs)
        } else if cfg!(target_os = "linux") {
            Some(Self::Linux)
        } else {
            None
        }
    }
}

/// macOS application bundles, best first, looked up under `/Applications` and
/// the person's own `~/Applications`.
const MAC_BUNDLES: &[&str] = &[
    "Google Chrome.app",
    "Microsoft Edge.app",
    "Chromium.app",
    "Brave Browser.app",
];

/// Linux launcher names, best first: the distribution packages' names, then
/// each browser's Flatpak application id (the name of its exported launcher).
const LINUX_NAMES: &[&str] = &[
    "google-chrome-stable",
    "google-chrome",
    "com.google.Chrome",
    "microsoft-edge-stable",
    "microsoft-edge",
    "com.microsoft.Edge",
    "chromium",
    "chromium-browser",
    "org.chromium.Chromium",
    "brave-browser",
    "brave-browser-stable",
    "com.brave.Browser",
];

/// Where Flatpak exports its launchers. Neither directory is on `PATH` (the
/// Flatpak profile script only extends `XDG_DATA_DIRS`), so a browser installed
/// that way is invisible to a `PATH` lookup alone.
const FLATPAK_SYSTEM_BIN: &str = "/var/lib/flatpak/exports/bin";
const FLATPAK_USER_BIN: &str = ".local/share/flatpak/exports/bin";

/// The first Chromium-family browser this machine has: an application bundle
/// on macOS, a launcher on Linux. `exists` answers for one candidate path, so
/// the rule is tested without a filesystem.
///
/// The order is a preference between browsers, not between directories: a
/// Chrome anywhere wins over an Edge anywhere.
pub fn find_browser(
    platform: Platform,
    exists: impl Fn(&Path) -> bool,
    path_dirs: &[PathBuf],
    home: Option<&Path>,
) -> Option<PathBuf> {
    let (names, dirs): (&[&str], Vec<PathBuf>) = match platform {
        Platform::MacOs => (
            MAC_BUNDLES,
            std::iter::once(PathBuf::from("/Applications"))
                .chain(home.map(|h| h.join("Applications")))
                .collect(),
        ),
        Platform::Linux => (
            LINUX_NAMES,
            path_dirs
                .iter()
                .cloned()
                .chain(std::iter::once(PathBuf::from(FLATPAK_SYSTEM_BIN)))
                .chain(home.map(|h| h.join(FLATPAK_USER_BIN)))
                .collect(),
        ),
    };
    names
        .iter()
        .flat_map(|name| dirs.iter().map(move |dir| dir.join(name)))
        // An empty `PATH` entry means the current directory; never run a
        // browser found by a relative path.
        .find(|candidate| candidate.is_absolute() && exists(candidate))
}

/// A program and its arguments.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Launch {
    pub program: PathBuf,
    pub args: Vec<OsString>,
}

/// The command that opens `url` as an app window of `browser` (what
/// [`find_browser`] returned).
///
/// ⚠️ macOS goes through LaunchServices (`open -n -a <bundle> --args …`), never
/// the bundle's executable. A browser started as the companion's child has the
/// companion as its *responsible process*: every privacy decision macOS makes
/// about that browser (Local Network, which the viewer's LAN candidates need;
/// camera; screen recording) is then asked and recorded under MeshHarbor's
/// name, and it stays that way for the person's ordinary browsing for as long
/// as that browser process lives. `-n` is required: without it `open` only
/// activates a browser that is already running and drops the arguments. With
/// it, the second instance hands its command line to the running one and
/// exits, and the window opens there.
///
/// ⚠️ No `--window-size`. A browser that was not running reads it for every
/// window it opens until it quits, the person's ordinary ones included.
pub fn launch_command(platform: Platform, browser: &Path, url: &str) -> Result<Launch, String> {
    // One argument either way, so nothing in the URL can become a switch of
    // its own; still, only ever a web address.
    if !(url.starts_with("http://") || url.starts_with("https://"))
        || url.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return Err("only http(s) URLs can be opened".to_string());
    }
    let app = OsString::from(format!("--app={url}"));
    Ok(match platform {
        Platform::MacOs => Launch {
            program: PathBuf::from("/usr/bin/open"),
            args: vec![
                "-n".into(),
                "-a".into(),
                browser.as_os_str().to_owned(),
                "--args".into(),
                app,
            ],
        },
        Platform::Linux => Launch {
            program: browser.to_path_buf(),
            args: vec![app],
        },
    })
}

/// Why the viewer did not get an app window.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NoAppWindow {
    /// This platform's viewer window is the companion's own.
    NotThisPlatform,
    /// No Chromium-family browser is installed.
    NoBrowser,
    /// One is installed and did not start.
    Failed { browser: PathBuf, error: String },
}

impl std::fmt::Display for NoAppWindow {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotThisPlatform => f.write_str("not used on this platform"),
            Self::NoBrowser => {
                f.write_str("no Chrome, Edge, Chromium or Brave is installed on this computer")
            }
            Self::Failed { browser, error } => {
                write!(f, "{} did not start: {error}", browser.display())
            }
        }
    }
}

/// Open `url` as an app window of the first Chromium-family browser found and
/// return that browser. Blocking (it waits for `open` on macOS): call it off
/// the UI thread. The caller falls back to the default browser on `Err`; the
/// URL has not been visited then.
pub fn open(url: &str) -> Result<PathBuf, NoAppWindow> {
    let platform = Platform::current().ok_or(NoAppWindow::NotThisPlatform)?;
    let path_dirs: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).collect())
        .unwrap_or_default();
    let home = std::env::var_os("HOME").map(PathBuf::from);
    let browser = find_browser(
        platform,
        |p| match platform {
            Platform::MacOs => p.is_dir(),
            Platform::Linux => p.is_file(),
        },
        &path_dirs,
        home.as_deref(),
    )
    .ok_or(NoAppWindow::NoBrowser)?;
    let failed = |error: String| NoAppWindow::Failed {
        browser: browser.clone(),
        error,
    };
    let launch = launch_command(platform, &browser, url).map_err(failed)?;
    let mut child = std::process::Command::new(&launch.program)
        .args(&launch.args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| failed(e.to_string()))?;
    match platform {
        // `open` returns once LaunchServices has started the browser, and its
        // status is the answer.
        Platform::MacOs => {
            let status = child.wait().map_err(|e| failed(e.to_string()))?;
            if !status.success() {
                return Err(failed(format!("open exited with {status}")));
            }
        }
        // The browser itself: it exits at once when it handed the window to a
        // running instance, and lives as long as its windows otherwise. Reap
        // it either way, and leave a trace when it ended badly.
        Platform::Linux => {
            let name = browser.clone();
            std::thread::spawn(move || match child.wait() {
                Ok(status) if !status.success() => {
                    tracing::warn!(browser = %name.display(), %status, "the app-window browser exited with an error");
                }
                _ => {}
            });
        }
    }
    Ok(browser)
}

#[cfg(test)]
mod tests {
    use super::*;

    const URL: &str = "http://127.0.0.1:49152/open/0123456789abcdef";

    fn only(paths: &'static [&'static str]) -> impl Fn(&Path) -> bool {
        move |p| paths.iter().any(|have| Path::new(have) == p)
    }

    #[test]
    fn macos_takes_the_best_bundle_in_either_applications_folder() {
        let home = Path::new("/Users/someone");
        let find = |have| find_browser(Platform::MacOs, only(have), &[], Some(home));
        assert_eq!(
            find(&["/Applications/Google Chrome.app"]),
            Some("/Applications/Google Chrome.app".into())
        );
        // A person's own Applications folder counts.
        assert_eq!(
            find(&["/Users/someone/Applications/Brave Browser.app"]),
            Some("/Users/someone/Applications/Brave Browser.app".into())
        );
        // The order is between browsers: Chrome in ~/Applications wins over
        // Edge in /Applications.
        assert_eq!(
            find(&[
                "/Applications/Microsoft Edge.app",
                "/Users/someone/Applications/Google Chrome.app",
            ]),
            Some("/Users/someone/Applications/Google Chrome.app".into())
        );
        // Safari and Firefox are not app-window browsers.
        assert_eq!(
            find(&["/Applications/Safari.app", "/Applications/Firefox.app"]),
            None
        );
        // PATH is not consulted on macOS.
        assert_eq!(
            find_browser(
                Platform::MacOs,
                only(&["/usr/bin/chromium"]),
                &[PathBuf::from("/usr/bin")],
                Some(home)
            ),
            None
        );
    }

    #[test]
    fn linux_takes_the_best_launcher_on_path_or_from_flatpak() {
        let home = Path::new("/home/someone");
        let path = [PathBuf::from("/usr/local/bin"), PathBuf::from("/usr/bin")];
        let find = |have| find_browser(Platform::Linux, only(have), &path, Some(home));
        assert_eq!(
            find(&["/usr/bin/chromium"]),
            Some("/usr/bin/chromium".into())
        );
        assert_eq!(
            find(&["/usr/bin/chromium", "/usr/bin/google-chrome-stable"]),
            Some("/usr/bin/google-chrome-stable".into())
        );
        // PATH order decides between two copies of the same browser.
        assert_eq!(
            find(&["/usr/bin/brave-browser", "/usr/local/bin/brave-browser"]),
            Some("/usr/local/bin/brave-browser".into())
        );
        // Flatpak's exported launchers are found although they are not on PATH.
        assert_eq!(
            find(&["/var/lib/flatpak/exports/bin/org.chromium.Chromium"]),
            Some("/var/lib/flatpak/exports/bin/org.chromium.Chromium".into())
        );
        assert_eq!(
            find(&["/home/someone/.local/share/flatpak/exports/bin/com.google.Chrome"]),
            Some("/home/someone/.local/share/flatpak/exports/bin/com.google.Chrome".into())
        );
        assert_eq!(find(&["/usr/bin/firefox", "/usr/bin/epiphany"]), None);
        // Nothing outside the search directories, and no macOS bundle.
        assert_eq!(
            find(&["/opt/chromium", "/Applications/Google Chrome.app"]),
            None
        );
    }

    #[test]
    fn a_relative_path_entry_never_names_the_browser() {
        // `PATH=:/usr/bin` and `PATH=.` both mean the current directory.
        let path = [PathBuf::from(""), PathBuf::from("."), PathBuf::from("bin")];
        assert_eq!(
            find_browser(Platform::Linux, |_| true, &path, None),
            Some("/var/lib/flatpak/exports/bin/google-chrome-stable".into())
        );
        assert_eq!(
            find_browser(
                Platform::Linux,
                |p| !p.starts_with("/var/lib/flatpak"),
                &path,
                None
            ),
            None
        );
    }

    #[test]
    fn linux_starts_the_browser_itself_with_one_app_argument() {
        let launch = launch_command(Platform::Linux, Path::new("/usr/bin/chromium"), URL).unwrap();
        assert_eq!(launch.program, PathBuf::from("/usr/bin/chromium"));
        assert_eq!(launch.args, vec![OsString::from(format!("--app={URL}"))]);
    }

    #[test]
    fn macos_starts_the_bundle_through_launch_services() {
        let launch = launch_command(
            Platform::MacOs,
            Path::new("/Applications/Google Chrome.app"),
            URL,
        )
        .unwrap();
        assert_eq!(launch.program, PathBuf::from("/usr/bin/open"));
        let want: Vec<OsString> = [
            "-n",
            "-a",
            "/Applications/Google Chrome.app",
            "--args",
            &format!("--app={URL}"),
        ]
        .iter()
        .map(OsString::from)
        .collect();
        assert_eq!(launch.args, want);
    }

    #[test]
    fn the_command_never_carries_a_window_size() {
        for platform in [Platform::MacOs, Platform::Linux] {
            let launch = launch_command(platform, Path::new("/x/browser"), URL).unwrap();
            assert!(
                launch
                    .args
                    .iter()
                    .all(|a| !a.to_string_lossy().starts_with("--window-")),
                "{launch:?}"
            );
        }
    }

    #[test]
    fn only_a_web_address_is_ever_handed_to_the_browser() {
        for bad in [
            "",
            "file:///etc/passwd",
            "javascript:alert(1)",
            "--user-data-dir=/tmp/x",
            "chrome://settings",
            "http://127.0.0.1:1/open/x --remote-debugging-port=9222",
            "http://127.0.0.1:1/open/x\n--incognito",
        ] {
            for platform in [Platform::MacOs, Platform::Linux] {
                assert!(
                    launch_command(platform, Path::new("/x/browser"), bad).is_err(),
                    "{bad:?}"
                );
            }
        }
        assert!(
            launch_command(
                Platform::Linux,
                Path::new("/x/browser"),
                "https://example.com/a"
            )
            .is_ok()
        );
    }

    #[test]
    fn the_reason_names_what_to_install() {
        let text = NoAppWindow::NoBrowser.to_string();
        for name in ["Chrome", "Edge", "Chromium", "Brave"] {
            assert!(text.contains(name), "{text}");
        }
    }
}
