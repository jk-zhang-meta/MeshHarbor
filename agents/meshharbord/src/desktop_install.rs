// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-120 P4 — a headless server gets a full desktop, installed by the daemon.
//!
//! The automatic virtual desktop (`virtual_desktop.rs`) shows whatever desktop
//! the host has. On a server that has none, that was a window manager and a
//! terminal, and the operator's requirement is a real desktop ("我不要只看到一个
//! 终端", 2026-11-19). So a ROOT daemon on a screenless host with no desktop
//! installed installs one itself, once, in the background, with the host's own
//! package manager, and switches the running virtual desktop to it.
//!
//! What it installs (Debian/Ubuntu `apt-get`, Fedora/RHEL `dnf`):
//! - Xfce: the desktop built to run on a plain X server with no GPU — the
//!   virtual display's case — with a terminal, file manager, editor, image
//!   viewer, task manager and the whisker menu;
//! - CJK and DejaVu fonts and an icon theme, so text and icons render;
//! - Xorg with the dummy driver and `xrandr`, so from the next daemon start
//!   the desktop's resolution follows the viewer's window (FR-108 display
//!   match), and Mesa's software GL for applications that need GL.
//!
//! What it never does:
//! - install a display manager (`--no-install-recommends`; a display manager
//!   would take the machine's own screen and switch the automatic desktop
//!   off at the next start);
//! - run as anything but root, or on a host with a screen (the caller only
//!   asks after `auto_decision` passed);
//! - run on a host with less than [`MIN_FREE_DISK`] free on `/` or less than
//!   [`MIN_MEMORY`] of RAM;
//! - try again within [`RETRY_AFTER`] of a failure (the state file says when).
//!
//! Kill switch: `MESHHARBORD_VIRTUAL_DESKTOP_INSTALL=0` (and
//! `MESHHARBORD_VIRTUAL_DESKTOP=0` switches the whole automatic desktop off).

use std::path::Path;
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use tracing::{info, warn};

/// Free space `/` must have before anything is downloaded.
pub const MIN_FREE_DISK: u64 = 3 << 30;
/// RAM the host must have: the desktop then stays a small share of it.
pub const MIN_MEMORY: u64 = 1536 << 20;
/// How long a failed install waits before the next daemon start tries again.
pub const RETRY_AFTER: Duration = Duration::from_secs(24 * 3600);
/// The whole install's ceiling.
const DEADLINE: Duration = Duration::from_secs(45 * 60);

const STATE_FILE: &str = "/var/lib/meshharbor/desktop-install.json";
const LOG_FILE: &str = "/var/log/meshharbor-desktop-install.log";

/// Debian/Ubuntu: the desktop, then what is merely nice to have. Each list is
/// filtered to the packages the host's archive carries, so a release that
/// lacks one (an old Ubuntu without the whisker menu) still gets the rest.
pub const APT_CORE: &[&str] = &[
    "xfce4",
    "xfce4-terminal",
    "dbus-x11",
    "at-spi2-core",
    "xvfb",
    "xserver-xorg-core",
    "xserver-xorg-video-dummy",
    "x11-xserver-utils",
    "libgl1-mesa-dri",
    "fonts-noto-cjk",
    "fonts-dejavu-core",
];
pub const APT_EXTRA: &[&str] = &[
    "xfce4-whiskermenu-plugin",
    "xfce4-taskmanager",
    "xfce4-notifyd",
    "mousepad",
    "ristretto",
    "thunar-archive-plugin",
    "papirus-icon-theme",
    "adwaita-icon-theme",
];
pub const DNF_PACKAGES: &[&str] = &[
    "xfce4-session",
    "xfwm4",
    "xfdesktop",
    "xfce4-panel",
    "xfce4-settings",
    "Thunar",
    "xfce4-terminal",
    "xfce4-whiskermenu-plugin",
    "xfce4-taskmanager",
    "mousepad",
    "dbus-x11",
    "xorg-x11-server-Xvfb",
    "xorg-x11-server-Xorg",
    "xorg-x11-drv-dummy",
    "xrandr",
    "mesa-dri-drivers",
    "google-noto-sans-cjk-fonts",
    "dejavu-sans-fonts",
    "papirus-icon-theme",
];

/// Which package manager the host has.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Manager {
    Apt,
    Dnf,
}

/// The facts the decision is made from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Facts {
    pub enabled: bool,
    pub root: bool,
    pub manager: Option<Manager>,
    pub free_disk: u64,
    pub memory: u64,
    /// Seconds since the last failed attempt, when there was one.
    pub since_failure: Option<u64>,
}

/// Should this host install a desktop now? `Ok(manager)` when yes, else why
/// not, for the log.
pub fn decide(f: &Facts) -> Result<Manager, &'static str> {
    if !f.enabled {
        return Err("switched off (VIRTUAL_DESKTOP_INSTALL=0)");
    }
    if !f.root {
        return Err("not a root daemon");
    }
    let Some(m) = f.manager else {
        return Err("no supported package manager (apt-get, dnf)");
    };
    if f.free_disk < MIN_FREE_DISK {
        return Err("less than 3 GiB free on /");
    }
    if f.memory < MIN_MEMORY {
        return Err("less than 1.5 GiB of RAM");
    }
    if f.since_failure.is_some_and(|s| s < RETRY_AFTER.as_secs()) {
        return Err("the last attempt failed less than a day ago");
    }
    Ok(m)
}

fn facts() -> Facts {
    let state = std::fs::read_to_string(STATE_FILE)
        .ok()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok());
    let since_failure = state.as_ref().and_then(|v| {
        (!v.get("ok")?.as_bool()?)
            .then(|| v.get("at")?.as_u64())
            .flatten()
            .map(|at| now().saturating_sub(at))
    });
    Facts {
        enabled: tunnel_core::env::flag("VIRTUAL_DESKTOP_INSTALL", true),
        // SAFETY: `geteuid` reads the caller's own credentials; it cannot fail.
        root: unsafe { libc::geteuid() } == 0,
        manager: if on_path("apt-get") {
            Some(Manager::Apt)
        } else if on_path("dnf") {
            Some(Manager::Dnf)
        } else {
            None
        },
        free_disk: free_disk("/"),
        memory: memory_total(),
        since_failure,
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn on_path(bin: &str) -> bool {
    std::env::var_os("PATH")
        .map(|p| std::env::split_paths(&p).any(|d| d.join(bin).is_file()))
        .unwrap_or(false)
        || Path::new("/usr/bin").join(bin).is_file()
}

fn free_disk(path: &str) -> u64 {
    let Ok(c) = std::ffi::CString::new(path) else {
        return 0;
    };
    // SAFETY: statvfs fills a zeroed struct for a valid NUL-terminated path.
    unsafe {
        let mut st: libc::statvfs = std::mem::zeroed();
        if libc::statvfs(c.as_ptr(), &mut st) != 0 {
            return 0;
        }
        st.f_bavail as u64 * st.f_frsize as u64
    }
}

fn memory_total() -> u64 {
    std::fs::read_to_string("/proc/meminfo")
        .ok()
        .and_then(|m| {
            m.lines()
                .find_map(|l| l.strip_prefix("MemTotal:"))
                .and_then(|r| r.split_whitespace().next()?.parse::<u64>().ok())
        })
        .map(|kib| kib << 10)
        .unwrap_or(0)
}

fn write_state(ok: bool, detail: &str) {
    let _ = std::fs::create_dir_all("/var/lib/meshharbor");
    let v = serde_json::json!({ "ok": ok, "at": now(), "detail": detail });
    let _ = std::fs::write(STATE_FILE, v.to_string());
}

/// FR-120 P4 — install a desktop in the background when this host should get
/// one, then switch the running virtual desktop to it. Never blocks, never
/// fails the caller.
pub fn spawn_if_needed() {
    let f = facts();
    let manager = match decide(&f) {
        Ok(m) => m,
        Err(why) => {
            info!(why, "virtual-desktop: no desktop install (FR-120 P4)");
            return;
        }
    };
    let spawned = std::thread::Builder::new()
        .name("desktop-install".into())
        .spawn(move || {
            info!(?manager, "virtual-desktop: installing a full desktop (Xfce) in the background — this host has none (FR-120 P4)");
            let started = std::time::Instant::now();
            match install(manager) {
                Ok(()) => match crate::virtual_desktop::installed_session() {
                    Some(session) => {
                        write_state(true, &session);
                        info!(%session, secs = started.elapsed().as_secs(), "virtual-desktop: full desktop installed");
                        if let Err(e) = crate::virtual_desktop::switch_to_session(&session) {
                            warn!(error = %format!("{e:#}"), "virtual-desktop: installed, but the running desktop could not switch; the next start uses it");
                        }
                    }
                    None => {
                        write_state(false, "installed, but no desktop session found");
                        warn!(log = LOG_FILE, "virtual-desktop: the install finished, but no desktop session is on PATH");
                    }
                },
                Err(e) => {
                    let detail = format!("{e:#}");
                    write_state(false, &detail);
                    warn!(error = %detail, log = LOG_FILE, "virtual-desktop: the desktop install failed; the next attempt is a day away");
                }
            }
        });
    if let Err(e) = spawned {
        warn!(%e, "virtual-desktop: could not start the desktop install");
    }
}

fn install(manager: Manager) -> Result<()> {
    let log = std::fs::OpenOptions::new()
        .create(true)
        .write(true)
        .truncate(true)
        .open(LOG_FILE)
        .with_context(|| format!("opening {LOG_FILE}"))?;
    let deadline = std::time::Instant::now() + DEADLINE;
    match manager {
        Manager::Apt => {
            let apt = |args: &[&str]| -> Command {
                let mut c = Command::new("apt-get");
                c.args([
                    "-o",
                    "DPkg::Lock::Timeout=900",
                    "-o",
                    "Dpkg::Options::=--force-confdef",
                    "-o",
                    "Dpkg::Options::=--force-confold",
                    "-q",
                    "-y",
                ])
                .args(args)
                .env("DEBIAN_FRONTEND", "noninteractive");
                c
            };
            run(apt(&["update"]), &log, deadline).context("apt-get update")?;
            let core = available_apt(APT_CORE);
            if !core.iter().any(|p| p == "xfce4") {
                bail!("this host's package archive has no xfce4");
            }
            let mut args = vec!["install", "--no-install-recommends"];
            args.extend(core.iter().map(String::as_str));
            run(apt(&args), &log, deadline).context("apt-get install (desktop)")?;
            let extra = available_apt(APT_EXTRA);
            if !extra.is_empty() {
                let mut args = vec!["install", "--no-install-recommends"];
                args.extend(extra.iter().map(String::as_str));
                if let Err(e) = run(apt(&args), &log, deadline) {
                    warn!(error = %format!("{e:#}"), "virtual-desktop: optional desktop extras did not install (the desktop did)");
                }
            }
        }
        Manager::Dnf => {
            let mut c = Command::new("dnf");
            c.args([
                "-y",
                "install",
                "--setopt=install_weak_deps=False",
                "--skip-broken",
            ])
            .args(DNF_PACKAGES);
            run(c, &log, deadline).context("dnf install")?;
        }
    }
    Ok(())
}

/// The packages of `wanted` the host's archive has a candidate for.
fn available_apt(wanted: &[&str]) -> Vec<String> {
    wanted
        .iter()
        .filter(|p| {
            Command::new("apt-cache")
                .args(["show", "--no-all-versions", p])
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .is_ok_and(|s| s.success())
        })
        .map(|p| p.to_string())
        .collect()
}

/// Run `cmd` at low priority, its output appended to the install log, killed
/// at `deadline`.
fn run(mut cmd: Command, log: &std::fs::File, deadline: std::time::Instant) -> Result<()> {
    let out = log.try_clone()?;
    let err = log.try_clone()?;
    cmd.stdin(Stdio::null()).stdout(out).stderr(err);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt as _;
        // SAFETY: setpriority in the child between fork and exec only.
        unsafe {
            cmd.pre_exec(|| {
                libc::setpriority(libc::PRIO_PROCESS, 0, 15);
                Ok(())
            });
        }
    }
    let mut child = cmd.spawn().context("spawning the package manager")?;
    loop {
        if let Some(status) = child.try_wait()? {
            if status.success() {
                return Ok(());
            }
            bail!("exited {status} (see {LOG_FILE})");
        }
        if std::time::Instant::now() > deadline {
            let _ = child.kill();
            let _ = child.wait();
            bail!("timed out after {} min", DEADLINE.as_secs() / 60);
        }
        std::thread::sleep(Duration::from_secs(2));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ok_facts() -> Facts {
        Facts {
            enabled: true,
            root: true,
            manager: Some(Manager::Apt),
            free_disk: 10 << 30,
            memory: 4 << 30,
            since_failure: None,
        }
    }

    /// FR-120 P4 — only a root daemon with room, a package manager, and no
    /// fresh failure installs; the switch always wins.
    #[test]
    fn only_a_root_host_with_room_installs() {
        assert_eq!(decide(&ok_facts()), Ok(Manager::Apt));
        let f = ok_facts();
        for bad in [
            Facts {
                enabled: false,
                ..f
            },
            Facts { root: false, ..f },
            Facts { manager: None, ..f },
            Facts {
                free_disk: 2 << 30,
                ..f
            },
            Facts {
                memory: 1 << 30,
                ..f
            },
            Facts {
                since_failure: Some(3600),
                ..f
            },
        ] {
            assert!(decide(&bad).is_err(), "{bad:?}");
        }
        assert!(
            decide(&Facts {
                since_failure: Some(RETRY_AFTER.as_secs() + 1),
                ..f
            })
            .is_ok()
        );
    }

    /// The package lists never name a display manager: one would take the
    /// machine's own screen and switch the automatic desktop off.
    #[test]
    fn no_display_manager_is_ever_installed() {
        for p in APT_CORE.iter().chain(APT_EXTRA).chain(DNF_PACKAGES) {
            for dm in ["lightdm", "gdm", "sddm", "lxdm", "slim", "xdm", "task-"] {
                assert!(!p.contains(dm), "{p}");
            }
        }
        assert!(APT_CORE.contains(&"xserver-xorg-video-dummy"));
    }
}
