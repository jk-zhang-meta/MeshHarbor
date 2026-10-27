// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! `--virtual-desktop` mode (Linux): bring up a headless X display (Xvfb)
//! plus a minimal window manager that the agent captures, turning a
//! Linux/WSL node into a browser-remotable desktop.
//!
//! WSLg's native display can't be screen-grabbed (rootless XWayland → the
//! X root has no readable framebuffer, `XGetImage` fails), so a dedicated
//! Xvfb is the capturable path — the same one `scripts/dev-xvfb.sh`
//! exercises. The agent's existing scrap (X11) capture + enigo input +
//! openh264/vp9 encode all work against it unchanged; this module is just
//! the orchestration.
//!
//! The code is cross-platform-compilable (`std::process` only) but only
//! wired in on Linux — the call site in `main::run_cmd` is
//! `#[cfg(target_os = "linux")]`.

use anyhow::{Context, Result, bail};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};
use tracing::{info, warn};

const X11_UNIX_DIR: &str = "/tmp/.X11-unix";

/// Is this daemon configured to run its OWN virtual desktop
/// (`VIRTUAL_DESKTOP=1` or `true`, through `node_env`: the env var under any
/// of its names, then the config)?
///
/// ⚠️ ONE copy. `main.rs` (whether to start one), the X11 indicator (a
/// virtual desktop is no consent surface) and the recorder (FR-85: a virtual
/// desktop is no login screen) all ask this. Two hand-rolled copies once
/// disagreed: one skipped `node_env`'s config fallback, so a knob set through
/// `meshharbor config` was seen by one and not the other.
pub fn requested() -> bool {
    tunnel_core::env::node_env("VIRTUAL_DESKTOP")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// How long the graceful teardown waits after SIGTERM before it SIGKILLs
/// whatever is left. Small on purpose: the virtual desktop's D-Bus tree —
/// `at-spi-bus-launcher` in particular — ignores SIGTERM, so the SIGKILL is
/// what actually reaps it, and every second here is a second the whole restart
/// (and every `systemctl stop`) is blocked. The point of doing this at all is
/// that systemd's own `TimeoutStopSec` for the same job is 90 s (#1684).
#[cfg(target_os = "linux")]
const TEARDOWN_GRACE: Duration = Duration::from_secs(2);

/// WSLg's PulseAudio server socket. When the agent runs inside WSL2 with
/// WSLg, the host's audio server is reachable here; exporting
/// `PULSE_SERVER` at it lets the virtual-desktop's apps (and thus the
/// `audio` feature's PulseAudio-monitor capture) actually route sound.
/// Without it, cpal's monitor source is silent under WSLg. On a native
/// Linux host this path doesn't exist and we leave `PULSE_SERVER`
/// untouched (the system default applies).
const WSLG_PULSE_SERVER: &str = "/mnt/wslg/PulseServer";

/// Add `PULSE_SERVER` pointing at the WSLg socket to `cmd`, but only when
/// that socket actually exists (i.e. we're under WSLg). No-op on native
/// Linux so the system default PulseAudio server is used.
fn with_wslg_pulse(cmd: &mut Command) {
    if Path::new(WSLG_PULSE_SERVER).exists() {
        cmd.env("PULSE_SERVER", WSLG_PULSE_SERVER);
    }
}

/// What to bring up: `WxH` resolution, a WM binary, and optional startup apps.
#[derive(Debug, Clone)]
pub struct Config {
    pub resolution: String,
    pub wm: String,
    pub startup: Vec<String>,
}

/// FR-108 P2 — the X server behind the desktop. Only Xorg with the dummy
/// driver can change its mode at runtime; Xvfb has one mode, its start size,
/// and `xrandr --newmode` there keeps nothing (spec §8 row 5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Server {
    Xvfb,
    XorgDummy,
}

/// The real Xorg binary, never the console-only wrapper, which refuses an
/// unprivileged caller that is not on a VT.
const XORG_BINARIES: &[&str] = &["/usr/lib/xorg/Xorg", "/usr/libexec/Xorg", "/usr/lib/Xorg"];

/// `xserver-xorg-video-dummy`, wherever a distribution puts its modules.
const DUMMY_DRIVERS: &[&str] = &[
    "/usr/lib/xorg/modules/drivers/dummy_drv.so",
    "/usr/lib64/xorg/modules/drivers/dummy_drv.so",
    "/usr/lib/x86_64-linux-gnu/xorg/modules/drivers/dummy_drv.so",
    "/usr/lib/aarch64-linux-gnu/xorg/modules/drivers/dummy_drv.so",
];

/// The dummy driver's framebuffer, in KiB: room for an 8K desktop.
pub const XORG_VIDEO_RAM_KIB: u64 = 256_000;

/// FR-108 P2 — the kill switch: `VIRTUAL_DESKTOP_SERVER=xvfb` (through
/// `node_env`: the env var under any of its names, then the config) keeps the
/// desktop on Xvfb, as before P2, wherever the dummy driver is installed.
fn server_forced_xvfb(raw: Option<&str>) -> bool {
    raw.is_some_and(|v| v.trim().eq_ignore_ascii_case("xvfb"))
}

/// FR-108 P2 — Xorg with the dummy driver, when the real binary, the driver
/// and `xrandr` (which switches its modes) are all installed and the kill
/// switch is not set. The first file of each list that exists is used.
fn xorg_dummy() -> Option<std::path::PathBuf> {
    if server_forced_xvfb(tunnel_core::env::node_env("VIRTUAL_DESKTOP_SERVER").as_deref()) {
        return None;
    }
    pick_xorg_dummy(
        |p| Path::new(p).is_file(),
        binary_on_path("xrandr").is_some(),
    )
}

/// [`xorg_dummy`]'s decision, with the filesystem behind `exists` so it is
/// testable.
fn pick_xorg_dummy(exists: impl Fn(&str) -> bool, xrandr: bool) -> Option<std::path::PathBuf> {
    let xorg = XORG_BINARIES.iter().find(|p| exists(p))?;
    if !DUMMY_DRIVERS.iter().any(|p| exists(p)) || !xrandr {
        return None;
    }
    Some(std::path::PathBuf::from(xorg))
}

/// FR-108 P2 — the dummy driver's config. The start mode is the configured
/// resolution exactly, as a `roomler-WxH` modeline: the dummy driver's own
/// default would be 2048x1536. ⚠️ `ReducedBlanking` is not decoration: the
/// modelines carry reduced blanking, and without the option Xorg drops the
/// start mode ("monitor doesn't support reduced blanking") and starts at its
/// default, leaving nothing named to restore to. No input devices: input
/// arrives through XTest, as on Xvfb, and a desktop that adds the host's real
/// devices would take the person's keyboard.
fn xorg_conf(w: u32, h: u32) -> String {
    let (name, timings) = crate::display_match::modeline(w, h);
    format!(
        r#"Section "ServerFlags"
  Option "AutoAddDevices" "false"
  Option "AutoEnableDevices" "false"
  Option "DontVTSwitch" "true"
  Option "BlankTime" "0"
  Option "StandbyTime" "0"
  Option "SuspendTime" "0"
  Option "OffTime" "0"
EndSection
Section "Device"
  Identifier "roomler-dummy"
  Driver "dummy"
  VideoRam {XORG_VIDEO_RAM_KIB}
EndSection
Section "Monitor"
  Identifier "roomler-monitor"
  HorizSync 1.0 - 2000.0
  VertRefresh 1.0 - 200.0
  Option "ReducedBlanking" "true"
  Modeline "{name}" {timings}
EndSection
Section "Screen"
  Identifier "roomler-screen"
  Device "roomler-dummy"
  Monitor "roomler-monitor"
  DefaultDepth 24
  SubSection "Display"
    Depth 24
    Virtual 3840 2160
    Modes "{name}"
  EndSubSection
EndSection
"#
    )
}

/// FR-108 P2 — the argv for Xorg with the dummy driver, unprivileged. Its own
/// `-configdir` (empty), so no `xorg.conf.d` snippet of the host's (a GPU's,
/// an input device's) leaks into the desktop. Like Xvfb's: no TCP, no access
/// control on the loopback socket, and no screen saver. `-dpms` too, since
/// Xorg, unlike Xvfb, carries DPMS and would blank the screen.
fn xorg_args(display: &str, conf: &Path, configdir: &Path, log: &Path) -> Vec<String> {
    vec![
        display.to_string(),
        "-config".into(),
        conf.display().to_string(),
        "-configdir".into(),
        configdir.display().to_string(),
        "-logfile".into(),
        log.display().to_string(),
        "-noreset".into(),
        "-nolisten".into(),
        "tcp".into(),
        "-ac".into(),
        "-s".into(),
        "0".into(),
        "-dpms".into(),
        "-novtswitch".into(),
        "-sharevts".into(),
    ]
}

/// Where the desktop's Xorg keeps its config and log: private to the daemon.
fn xorg_dir(display: &str) -> std::path::PathBuf {
    std::env::temp_dir().join(format!("roomler-xorg-{}", display.trim_start_matches(':')))
}

/// The running desktop's display and server, for display match (FR-108 P2).
static SERVER: std::sync::Mutex<Option<(String, Server)>> = std::sync::Mutex::new(None);

/// FR-108 P2 — the display of this daemon's own virtual desktop when its
/// server can change mode (Xorg with the dummy driver); `None` otherwise,
/// including on Xvfb and when no virtual desktop runs.
pub fn switchable_display() -> Option<String> {
    match &*SERVER.lock().unwrap_or_else(|e| e.into_inner()) {
        Some((d, Server::XorgDummy)) => Some(d.clone()),
        _ => None,
    }
}

/// FR-97 P3e-2 — this daemon runs its own virtual desktop, on any server: its
/// `DISPLAY` is that desktop's, not a person's X11 display.
pub fn active() -> bool {
    SERVER.lock().unwrap_or_else(|e| e.into_inner()).is_some()
}

/// A running virtual desktop. Its `Drop` tears the whole process tree down
/// (see [`teardown`]), so the caller keeps the handle alive for the agent's
/// lifetime.
pub struct VirtualDesktop {
    display: String,
    #[cfg_attr(target_os = "linux", allow(dead_code))]
    children: Vec<Child>,
}

impl VirtualDesktop {
    /// The `:N` display the agent should capture (export as `DISPLAY`).
    pub fn display(&self) -> &str {
        &self.display
    }
}

impl Drop for VirtualDesktop {
    fn drop(&mut self) {
        // Linux: the desktop is a whole process tree that outlives its direct
        // children (a setsid'd `at-spi-bus-launcher` grandchild, D-Bus), so
        // `Child::kill` on our own children would leave the rest in the unit's
        // cgroup for systemd's `TimeoutStopSec` (90 s) to reap. `teardown`
        // reaches every descendant and is idempotent, so calling it here (as
        // the RAII backstop) after `run_cmd` already called it explicitly is a
        // no-op the second time.
        #[cfg(target_os = "linux")]
        teardown();
        // Every other platform never enters `start` (the call site is
        // `#[cfg(target_os = "linux")]`); keep the simple child kill for the
        // struct's own invariants and for a hypothetical future caller.
        #[cfg(not(target_os = "linux"))]
        for c in &mut self.children {
            let _ = c.kill();
        }
    }
}

// ---------------------------------------------------------------------------
// Teardown — reach every descendant, not just our direct children (#1684)
// ---------------------------------------------------------------------------
//
// The failure this fixes: on a host running a virtual desktop, `roomler
// restart` took 96 s and the CLI reported failure at 60 s though the restart
// worked. The daemon runs under systemd `KillMode=control-group`,
// `TimeoutStopSec=90s`; once the daemon exits, systemd must empty the unit's
// cgroup, and the desktop's `at-spi-bus-launcher` — a setsid'd grandchild that
// ignores SIGTERM — kept the cgroup non-empty until systemd SIGKILLed it 90 s
// later, then paid `RestartSec` on top.
//
// So the daemon takes its own desktop down before it leaves. Two facts shape
// how:
//
//   * The children are spawned into a dedicated process GROUP ([`start`]), so
//     `killpg` reaches every one that stayed in it — but a grandchild that
//     called `setsid` (at-spi, a D-Bus service) has left the group.
//   * `setsid` changes the session and the group, never the PARENT, so a
//     descendant is still reachable by walking `/proc` parent links down from
//     our direct children. We snapshot `/proc` BEFORE signalling anything, so
//     the links are still intact (nothing has been reparented to init yet).
//
// The union of the two — group members and the parent-link closure of our
// children — is every process the daemon spawned for the desktop, and nothing
// else. SIGTERM, a short grace, then SIGKILL for the SIGTERM-deaf remainder.

/// The desktop's process group and the direct children we spawned, recorded
/// when [`start`] succeeds so [`teardown`] can run without the
/// [`VirtualDesktop`] handle — the graceful exit paths (`exit_for_requested_restart`,
/// the SIGTERM arm of `run_cmd`) reach it as a free function.
#[cfg(target_os = "linux")]
static VD_TREE: std::sync::Mutex<Option<TreeHandle>> = std::sync::Mutex::new(None);

#[cfg(target_os = "linux")]
#[derive(Clone)]
struct TreeHandle {
    /// The process group all our children were placed in (`None` if we could
    /// not create one — then only the parent-link closure is used).
    pgid: Option<i32>,
    /// The pids of the processes the daemon spawned directly (Xvfb, the WM,
    /// the startup apps).
    roots: Vec<i32>,
}

/// One process, as `/proc` reports it, for [`select_targets`] — and, through
/// `starttime`, an IDENTITY. A pid is recycled by the kernel once the process
/// that held it is reaped; a (pid, starttime) pair is not, within one boot. This
/// code SIGKILLs as root, so before it signals any process that is not its own
/// unreaped child it proves the pid still means what the snapshot saw
/// ([`same_process`]).
#[cfg(target_os = "linux")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ProcInfo {
    pid: i32,
    ppid: i32,
    pgid: i32,
    /// Field 22 of `/proc/<pid>/stat`: when the process started, in clock
    /// ticks since boot. A recycled pid carries a later one.
    starttime: u64,
}

/// The pids to signal: everything in our process group, plus the transitive
/// parent-link closure of `roots` — the desktop's whole tree including
/// grandchildren that `setsid`'d out of the group. Never `self_pid` (the
/// daemon), pid 0, or pid 1, whatever the links say. Pure, so the selection is
/// unit-tested against synthetic `/proc` snapshots.
#[cfg(target_os = "linux")]
fn select_targets(
    snapshot: &[ProcInfo],
    roots: &[i32],
    pgid: Option<i32>,
    self_pid: i32,
) -> std::collections::BTreeSet<i32> {
    use std::collections::BTreeSet;
    let mut targets: BTreeSet<i32> = BTreeSet::new();
    // Group members.
    if let Some(g) = pgid.filter(|g| *g > 1) {
        for p in snapshot.iter().filter(|p| p.pgid == g) {
            targets.insert(p.pid);
        }
    }
    // The direct children we hold, even if `/proc` no longer lists them.
    for &r in roots {
        if r > 1 {
            targets.insert(r);
        }
    }
    // Parent-link closure: repeatedly pull in any process whose parent is
    // already a target. Bounded by the snapshot size — each pass adds at least
    // one pid or we stop.
    loop {
        let mut grew = false;
        for p in snapshot {
            if p.pid > 1 && !targets.contains(&p.pid) && targets.contains(&p.ppid) {
                targets.insert(p.pid);
                grew = true;
            }
        }
        if !grew {
            break;
        }
    }
    // Never the daemon itself, and never pid 0/1 — a stray link to them is a
    // reparenting we must not follow into.
    targets.remove(&self_pid);
    targets.remove(&0);
    targets.remove(&1);
    targets
}

/// Read `/proc` into [`ProcInfo`]s. Linux-only.
#[cfg(target_os = "linux")]
fn read_proc_snapshot() -> Vec<ProcInfo> {
    let mut out = Vec::new();
    let Ok(entries) = std::fs::read_dir("/proc") else {
        return out;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(name) = name.to_str() else { continue };
        let Ok(pid) = name.parse::<i32>() else {
            continue;
        };
        if let Some(info) = read_proc_stat(pid) {
            out.push(info);
        }
    }
    out
}

/// The fields this module reads from one `/proc/<pid>/stat` line: state (f3),
/// ppid (f4), pgrp (f5) and starttime (f22). The comm field (f2) is
/// parenthesised and may itself contain spaces and `)`, so split on the LAST
/// `)` and count space-separated fields from there — field `k` sits at index
/// `k - 3`. `None` if any of the four is missing or unparseable.
#[cfg(target_os = "linux")]
fn parse_stat(raw: &str) -> Option<(&str, i32, i32, u64)> {
    let rparen = raw.rfind(')')?;
    let fields: Vec<&str> = raw[rparen + 1..].split_whitespace().collect();
    let state = fields.first()?;
    let ppid = fields.get(1)?.parse::<i32>().ok()?;
    let pgid = fields.get(2)?.parse::<i32>().ok()?;
    let starttime = fields.get(19)?.parse::<u64>().ok()?;
    Some((state, ppid, pgid, starttime))
}

/// Read `/proc/<pid>/stat` into a [`ProcInfo`]. Linux-only.
#[cfg(target_os = "linux")]
fn read_proc_stat(pid: i32) -> Option<ProcInfo> {
    let raw = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let (_state, ppid, pgid, starttime) = parse_stat(&raw)?;
    Some(ProcInfo {
        pid,
        ppid,
        pgid,
        starttime,
    })
}

/// Is the process that `/proc/<pid>/stat` NOW describes (`current_stat`) the
/// same one `snapshot` recorded? Equal starttimes say yes. Pure; `false` for
/// anything unparseable — when in doubt, do not signal.
#[cfg(target_os = "linux")]
fn same_process(snapshot: &ProcInfo, current_stat: &str) -> bool {
    matches!(parse_stat(current_stat), Some((_, _, _, st)) if st == snapshot.starttime)
}

/// Is `pid` a live process (not gone, not a zombie/dead)? A zombie still
/// answers `kill(pid, 0)` until it is reaped, so liveness reads the `/proc`
/// state rather than signalling.
#[cfg(target_os = "linux")]
fn is_running(pid: i32) -> bool {
    match std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        Ok(raw) => match raw.rfind(')') {
            Some(rp) => !matches!(
                raw[rp + 1..].split_whitespace().next(),
                Some("Z") | Some("X") | Some("x") | None
            ),
            None => false,
        },
        Err(_) => false,
    }
}

/// SIGTERM the desktop tree, wait a bounded grace, SIGKILL the remainder, and
/// reap our direct children. Idempotent: takes the recorded tree, so a second
/// call finds nothing and returns at once. Safe to call from every graceful
/// exit path and from `Drop`.
///
/// No-op on non-Linux (the desktop is Linux-only) and no-op when no desktop was
/// started.
pub fn teardown() {
    #[cfg(target_os = "linux")]
    {
        let handle = {
            let mut guard = VD_TREE.lock().unwrap_or_else(|e| e.into_inner());
            guard.take()
        };
        let Some(handle) = handle else { return };
        kill_tree(&handle.roots, handle.pgid, TEARDOWN_GRACE);
        // FR-108 P2 — the desktop is gone, so nothing is left to switch.
        if let Some((dpy, server)) = SERVER.lock().unwrap_or_else(|e| e.into_inner()).take()
            && server == Server::XorgDummy
        {
            let _ = std::fs::remove_dir_all(xorg_dir(&dpy));
        }
    }
}

/// The process operations [`kill_tree_with`] performs, behind a seam so that
/// the ORDER they happen in — every signal before any reap, every non-root
/// signal behind an identity check — is provable in a unit test without a
/// process tree. [`RealProcs`] is `/proc` + libc; the tests script one.
#[cfg(target_os = "linux")]
trait Procs {
    /// Every process `/proc` lists right now.
    fn snapshot(&mut self) -> Vec<ProcInfo>;
    /// `pid` is a live (not gone, not zombie) process.
    fn is_running(&mut self, pid: i32) -> bool;
    /// `info.pid` is still the process `info` recorded — same starttime
    /// ([`same_process`]). `false` if it is gone, recycled or unreadable.
    fn same_process_now(&mut self, info: &ProcInfo) -> bool;
    fn signal(&mut self, pid: i32, sig: i32);
    fn killpg(&mut self, pgid: i32, sig: i32);
    /// `waitpid(WNOHANG)` each root. `true` once none of them is still an
    /// unreaped child of ours.
    fn reap(&mut self, roots: &[i32]) -> bool;
    fn sleep(&mut self, d: Duration);
}

/// The real thing. Linux-only.
#[cfg(target_os = "linux")]
struct RealProcs;

#[cfg(target_os = "linux")]
impl Procs for RealProcs {
    fn snapshot(&mut self) -> Vec<ProcInfo> {
        read_proc_snapshot()
    }
    fn is_running(&mut self, pid: i32) -> bool {
        is_running(pid)
    }
    fn same_process_now(&mut self, info: &ProcInfo) -> bool {
        std::fs::read_to_string(format!("/proc/{}/stat", info.pid))
            .is_ok_and(|raw| same_process(info, &raw))
    }
    fn signal(&mut self, pid: i32, sig: i32) {
        if pid > 1 {
            // SAFETY: a plain `kill(2)`. `kill_tree_with` calls this only for
            // (a) one of OUR direct children, which stays an unreaped zombie
            // until the final `reap`, so its pid is reserved by the kernel and
            // cannot have been recycled, or (b) a pid whose `/proc` starttime
            // was re-read and matched the snapshot an instant ago
            // (`same_process_now`). A failure (ESRCH: gone in between) is
            // exactly what we want and not actionable.
            unsafe {
                libc::kill(pid, sig);
            }
        }
    }
    fn killpg(&mut self, pgid: i32, sig: i32) {
        if pgid > 1 {
            // SAFETY: `killpg(2)` on the group WE created in `start`. Its id is
            // Xvfb's pid — one of our roots — which stays reserved (an
            // unreaped zombie at worst) until the final `reap`, so the group id
            // cannot have been handed to an unrelated group in the meantime.
            unsafe {
                libc::killpg(pgid, sig);
            }
        }
    }
    fn reap(&mut self, roots: &[i32]) -> bool {
        let mut all_done = true;
        for &pid in roots {
            if pid > 1 {
                let mut status: libc::c_int = 0;
                // SAFETY: `waitpid` on our own child with `WNOHANG`. Returns the
                // pid once reaped, 0 while it still runs, -1/ECHILD if it is not
                // (or no longer) our child — the last two need no action.
                let r = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
                if r == 0 {
                    all_done = false;
                }
            }
        }
        all_done
    }
    fn sleep(&mut self, d: Duration) {
        std::thread::sleep(d);
    }
}

/// The teardown itself, separated from the global so a test can drive it
/// against a tree it built. Linux-only.
#[cfg(target_os = "linux")]
fn kill_tree(roots: &[i32], pgid: Option<i32>, grace: Duration) {
    kill_tree_with(&mut RealProcs, roots, pgid, grace);
}

/// SIGTERM the tree, wait `grace`, SIGKILL what is left, wait for the kills to
/// land, and only THEN reap our children. Two rules keep a root-privileged
/// SIGKILL off a recycled pid, and both are load-bearing:
///
/// 1. **Nothing is reaped until every signal has been sent.** An unreaped zombie
///    keeps its pid reserved — and, for the group leader (Xvfb), the desktop's
///    pgid with it — so `kill(root)` and both `killpg(pgid)` calls cannot land
///    on an id the kernel has handed to someone else. Reaping inside the grace
///    loop (the first cut of this code) freed exactly those numbers
///    mid-teardown. [`is_running`] already reads a zombie as not running, so the
///    grace and settle checks need no reaping to terminate.
/// 2. **A pid that is not one of our children is signalled only after its
///    `/proc` starttime is re-read and matches the snapshot that selected it.**
///    Grandchildren are reaped by their parent or init the moment they exit, so
///    their numbers CAN be recycled during the grace; the (pid, starttime) pair
///    cannot. Each pass checks against its own snapshot — never a fresher one,
///    which might already describe the recycled process.
#[cfg(target_os = "linux")]
fn kill_tree_with(p: &mut dyn Procs, roots: &[i32], pgid: Option<i32>, grace: Duration) {
    use std::collections::{BTreeSet, HashMap};
    let self_pid = std::process::id() as i32;
    let is_root = |pid: i32| roots.contains(&pid);
    let group = pgid.filter(|g| *g > 1);

    // Pass 1 — SIGTERM. Snapshot BEFORE any signal, so the parent links are
    // still intact (nothing has been reparented to init yet).
    let snap = p.snapshot();
    let targets = select_targets(&snap, roots, pgid, self_pid);
    if targets.is_empty() {
        return;
    }
    let ident: HashMap<i32, ProcInfo> = snap.iter().map(|i| (i.pid, *i)).collect();
    info!(
        count = targets.len(),
        ?pgid,
        "virtual-desktop: tearing down the desktop process tree (SIGTERM)"
    );
    for &pid in &targets {
        if is_root(pid) {
            p.signal(pid, libc::SIGTERM);
        } else if let Some(info) = ident.get(&pid)
            && p.same_process_now(info)
        {
            p.signal(pid, libc::SIGTERM);
        }
    }
    // The group as a whole, for anything that appeared after the snapshot but
    // stayed in the group.
    if let Some(g) = group {
        p.killpg(g, libc::SIGTERM);
    }

    // Grace: poll until nothing is running, or the deadline hits. No reaping
    // here — see rule 1.
    let deadline = Instant::now() + grace;
    loop {
        if !targets.iter().any(|&t| p.is_running(t)) {
            break;
        }
        if Instant::now() >= deadline {
            break;
        }
        p.sleep(Duration::from_millis(50));
    }

    // Pass 2 — SIGKILL whatever ignored SIGTERM (at-spi does). A fresh snapshot
    // catches anything that forked during the grace; each pid's identity is
    // checked against the snapshot that SELECTED it (rule 2).
    let snap2 = p.snapshot();
    let survivors = select_targets(&snap2, roots, pgid, self_pid);
    let ident2: HashMap<i32, ProcInfo> = snap2.iter().map(|i| (i.pid, *i)).collect();
    let kill_set: BTreeSet<i32> = targets.union(&survivors).copied().collect();
    let mut killed = 0usize;
    for &pid in &kill_set {
        if !p.is_running(pid) {
            continue;
        }
        let ours = if is_root(pid) {
            true
        } else if survivors.contains(&pid) {
            ident2.get(&pid).is_some_and(|i| p.same_process_now(i))
        } else {
            ident.get(&pid).is_some_and(|i| p.same_process_now(i))
        };
        if ours {
            p.signal(pid, libc::SIGKILL);
            killed += 1;
        }
    }
    if let Some(g) = group {
        p.killpg(g, libc::SIGKILL);
    }

    // Settle: wait for the SIGKILLs to actually take effect. A process the
    // kernel has been told to SIGKILL lingers a few ms in `/proc` as R/S before
    // it is torn down, and the whole point is that when the daemon exits,
    // systemd finds the cgroup EMPTY. Bounded. Still no reaping.
    let settle = Instant::now() + Duration::from_secs(1);
    while Instant::now() < settle {
        if !kill_set.iter().any(|&t| p.is_running(t)) {
            break;
        }
        p.sleep(Duration::from_millis(20));
    }
    if killed > 0 {
        info!(
            killed,
            "virtual-desktop: SIGKILLed processes that ignored SIGTERM"
        );
    }

    // Reap LAST — and only now (rule 1). Bounded, so the unit's cgroup does not
    // keep our zombies: they were SIGKILLed above and exit within milliseconds.
    let reap_by = Instant::now() + Duration::from_secs(1);
    while !p.reap(roots) && Instant::now() < reap_by {
        p.sleep(Duration::from_millis(20));
    }
}

/// Bring up Xvfb + WM + startup apps. Errors (with an actionable message)
/// if the required binaries are missing or Xvfb doesn't come up.
pub fn start(cfg: &Config) -> Result<VirtualDesktop> {
    preflight(cfg)?;
    let (w, h) = parse_resolution(&cfg.resolution);
    let mut children = Vec::new();

    let (x, server, dpy) = spawn_x_server(w, h)?;
    // The desktop's group id is the X server's pid (a group leader's pgid ==
    // its pid).
    let pgid = group_of(&x);
    children.push(x);
    *SERVER.lock().unwrap_or_else(|e| e.into_inner()) = Some((dpy.clone(), server));
    info!(display = dpy.as_str(), resolution = %cfg.resolution, ?server, "virtual-desktop: X server up");

    let mut wm_cmd = Command::new(&cfg.wm);
    wm_cmd
        .env("DISPLAY", &dpy)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    with_wslg_pulse(&mut wm_cmd);
    join_group(&mut wm_cmd, pgid);
    match wm_cmd.spawn() {
        Ok(c) => children.push(c),
        Err(e) => {
            warn!(wm = %cfg.wm, %e, "virtual-desktop: window manager failed to start (continuing bare)")
        }
    }

    for app in &cfg.startup {
        let mut app_cmd = Command::new(app);
        app_cmd
            .env("DISPLAY", &dpy)
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        with_wslg_pulse(&mut app_cmd);
        join_group(&mut app_cmd, pgid);
        match app_cmd.spawn() {
            Ok(c) => children.push(c),
            Err(e) => warn!(%app, %e, "virtual-desktop: startup app failed to launch"),
        }
    }
    info!(display = dpy.as_str(), wm = %cfg.wm, apps = cfg.startup.len(), ?pgid, "virtual-desktop ready");
    // Record the tree so `teardown` can reach it without the handle, on the
    // graceful exit paths that run as free functions. One desktop per daemon,
    // so a plain overwrite is right.
    #[cfg(target_os = "linux")]
    {
        let roots: Vec<i32> = children.iter().map(|c| c.id() as i32).collect();
        *VD_TREE.lock().unwrap_or_else(|e| e.into_inner()) = Some(TreeHandle { pgid, roots });
    }
    Ok(VirtualDesktop {
        display: dpy,
        children,
    })
}

/// Spawn the desktop's X server on a free display and wait for its socket.
/// FR-108 P2: Xorg with the dummy driver where it is installed, so display
/// match can switch its mode; Xvfb otherwise, and also when Xorg does not come
/// up, so a failing Xorg costs only the switch, never the desktop. The server
/// LEADS a new process group of its own (`process_group(0)`), so the whole
/// desktop tree is separable from the daemon and can be torn down as a unit
/// (#1684) without ever signalling the daemon or its other children.
fn spawn_x_server(w: u32, h: u32) -> Result<(Child, Server, String)> {
    if let Some(xorg) = xorg_dummy() {
        let dpy = pick_display(X11_UNIX_DIR);
        match spawn_xorg(&xorg, &dpy, w, h) {
            Ok(mut child) => match wait_display_ready(&dpy, Duration::from_secs(15)) {
                Ok(()) => return Ok((child, Server::XorgDummy, dpy)),
                Err(e) => {
                    let _ = child.kill();
                    let _ = child.wait();
                    warn!(%e, log = %xorg_dir(&dpy).join("Xorg.log").display(), "virtual-desktop: Xorg with the dummy driver did not come up — using Xvfb, so display match answers unsupported");
                }
            },
            Err(e) => {
                warn!(%e, "virtual-desktop: could not start Xorg with the dummy driver — using Xvfb, so display match answers unsupported")
            }
        }
    }
    // Picked afresh: a failed Xorg may have left its lock behind on the first.
    let dpy = pick_display(X11_UNIX_DIR);
    let mut cmd = Command::new("Xvfb");
    cmd.args(xvfb_args(&dpy, w, h))
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    lead_new_group(&mut cmd);
    let mut child = cmd.spawn().context("spawn Xvfb")?;
    if let Err(e) = wait_display_ready(&dpy, Duration::from_secs(15)) {
        // No `VirtualDesktop` yet, so Drop won't fire: kill what we spawned.
        let _ = child.kill();
        return Err(e);
    }
    Ok((child, Server::Xvfb, dpy))
}

/// FR-108 P2 — start Xorg with the dummy driver on `dpy`, its config and log
/// in a directory of its own.
fn spawn_xorg(xorg: &Path, dpy: &str, w: u32, h: u32) -> Result<Child> {
    let dir = xorg_dir(dpy);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("conf.d")).context("creating the Xorg directory")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
    }
    let conf = dir.join("xorg.conf");
    std::fs::write(&conf, xorg_conf(w, h)).context("writing xorg.conf")?;
    let mut cmd = Command::new(xorg);
    cmd.args(xorg_args(
        dpy,
        &conf,
        &dir.join("conf.d"),
        &dir.join("Xorg.log"),
    ))
    .stdout(Stdio::null())
    .stderr(Stdio::null());
    lead_new_group(&mut cmd);
    cmd.spawn().context("spawn Xorg")
}

/// Place a child at the head of a NEW process group (`setpgid(0, 0)` before
/// exec). Linux-only; a no-op elsewhere (the desktop is never started there).
#[cfg(target_os = "linux")]
fn lead_new_group(cmd: &mut Command) {
    use std::os::unix::process::CommandExt as _;
    cmd.process_group(0);
}
#[cfg(not(target_os = "linux"))]
fn lead_new_group(_cmd: &mut Command) {}

/// Place a child INTO the desktop's process group, if we have one. Linux-only.
#[cfg(target_os = "linux")]
fn join_group(cmd: &mut Command, pgid: Option<i32>) {
    use std::os::unix::process::CommandExt as _;
    if let Some(g) = pgid.filter(|g| *g > 1) {
        cmd.process_group(g);
    }
}
#[cfg(not(target_os = "linux"))]
fn join_group(_cmd: &mut Command, _pgid: Option<i32>) {}

/// The process group Xvfb leads — its pid, since we made it a group leader.
/// `None` on non-Linux. Reading it back from `/proc` would race a just-exec'd
/// child, so we take the leader's pid, which IS the group id by construction.
#[cfg(target_os = "linux")]
fn group_of(leader: &Child) -> Option<i32> {
    Some(leader.id() as i32)
}
#[cfg(not(target_os = "linux"))]
fn group_of(_leader: &Child) -> Option<i32> {
    None
}

/// The Xvfb command line for one virtual desktop.
///
/// Extracted from `start` so the flags are assertable — the screen-saver
/// disable below is invisible at runtime until it has already cost someone a
/// black screen, which is not a thing to leave un-locked.
fn xvfb_args(display: &str, w: u32, h: u32) -> Vec<String> {
    vec![
        display.to_string(),
        "-screen".into(),
        "0".into(),
        format!("{w}x{h}x24"),
        // No access control: the agent may run as root while the desktop is
        // owned by another user, and this is a loopback-only server.
        "-ac".into(),
        "-nolisten".into(),
        "tcp".into(),
        // A remote-desktop host must never blank itself. X's BUILT-IN screen
        // saver defaults to ~10 minutes and there is no local keyboard here to
        // wake it, so without this the operator eventually connects to a black
        // screen — and capture reports it faithfully, which reads as a broken
        // stream rather than a blanked one. `-s 0` disables that timeout.
        //
        // Deliberately NOT `-dpms`: Xvfb has no DPMS extension at all
        // (`Xlib: extension "DPMS" missing` on the display it serves), so the
        // flag would be inert noise. And this reaches the X SERVER only — a
        // full DE started through VIRTUAL_DESKTOP_WM/_STARTUP brings its own
        // screensaver (xfce4-screensaver blanked and then LOCKED a field host
        // on 2026-08-29, costing a measurement round), which is that DE's
        // setting to turn off and not something a server flag can reach.
        "-s".into(),
        "0".into(),
    ]
}

/// Confirm the required binaries exist, else bail with the apt line.
fn preflight(cfg: &Config) -> Result<()> {
    let mut missing = Vec::new();
    // FR-108 P2 — Xorg with the dummy driver needs no Xvfb.
    if xorg_dummy().is_none() && binary_on_path("Xvfb").is_none() {
        missing.push("xvfb".to_string());
    }
    if binary_on_path(&cfg.wm).is_none() {
        missing.push(cfg.wm.clone());
    }
    if !missing.is_empty() {
        bail!(
            "virtual-desktop: missing required binaries. Install them, e.g.:\n    sudo apt install {}",
            missing.join(" ")
        );
    }
    Ok(())
}

/// Is `bin` an executable on `$PATH`? Absolute/relative paths are checked
/// directly. Cross-platform (uses `PATH` + the platform separator).
fn binary_on_path(bin: &str) -> Option<std::path::PathBuf> {
    if bin.contains('/') || bin.contains('\\') {
        let p = std::path::PathBuf::from(bin);
        return p.is_file().then_some(p);
    }
    let path = std::env::var_os("PATH")?;
    std::env::split_paths(&path).find_map(|dir| {
        let cand = dir.join(bin);
        cand.is_file().then_some(cand)
    })
}

/// Pick a free `:N` (`:99..=:120`) by requiring BOTH a missing X socket
/// (`<x11_dir>/X<N>`) AND a missing lock (`/tmp/.X<N>-lock`). Xvfb refuses a
/// display whose lock file exists even when the socket is gone — a crash-loop
/// leaves stale `/tmp/.X<N>-lock` behind, which is exactly the WSL failure
/// mode — so skip any display that still has one. Falls back to `:99`.
fn pick_display(x11_dir: &str) -> String {
    for n in 99..=120 {
        let socket = Path::new(x11_dir).join(format!("X{n}"));
        let lock = Path::new("/tmp").join(format!(".X{n}-lock"));
        if !socket.exists() && !lock.exists() {
            return format!(":{n}");
        }
    }
    ":99".to_string()
}

/// `"1920x1080"` → `(1920, 1080)`; anything unparseable → `(1920, 1080)`.
fn parse_resolution(s: &str) -> (u32, u32) {
    let mut it = s.split(['x', 'X']);
    match (
        it.next().and_then(|v| v.trim().parse::<u32>().ok()),
        it.next().and_then(|v| v.trim().parse::<u32>().ok()),
    ) {
        (Some(w), Some(h)) if w > 0 && h > 0 => (w, h),
        _ => {
            warn!(resolution = %s, "virtual-desktop: unparseable resolution — using 1920x1080");
            (1920, 1080)
        }
    }
}

/// Poll for the Xvfb X socket to appear, then a short settle.
fn wait_display_ready(display: &str, timeout: Duration) -> Result<()> {
    let n = display.trim_start_matches(':');
    let sock = Path::new(X11_UNIX_DIR).join(format!("X{n}"));
    let start = Instant::now();
    while start.elapsed() < timeout {
        if sock.exists() {
            std::thread::sleep(Duration::from_millis(300));
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(200));
    }
    bail!("virtual-desktop: X server display {display} did not become ready within {timeout:?}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The screen-saver disable is the whole point of this argv and is
    /// invisible at runtime until it has already blanked someone's session,
    /// so assert it as a pair rather than trusting the flag survived an edit.
    #[test]
    fn xvfb_args_disable_the_builtin_screen_saver() {
        let a = xvfb_args(":99", 1920, 1080);
        let i = a
            .iter()
            .position(|s| s == "-s")
            .expect("Xvfb must be told to disable the screen saver");
        assert_eq!(
            a.get(i + 1).map(String::as_str),
            Some("0"),
            "-s must be 0 (disabled); any other value is a TIMEOUT, not a disable"
        );
        // -dpms would be inert here: Xvfb ships no DPMS extension.
        assert!(!a.iter().any(|s| s == "-dpms"));
    }

    #[test]
    fn xvfb_args_carry_the_display_and_geometry() {
        let a = xvfb_args(":7", 1280, 720);
        assert_eq!(a.first().map(String::as_str), Some(":7"));
        assert!(a.iter().any(|s| s == "1280x720x24"), "got {a:?}");
        assert!(a.iter().any(|s| s == "-ac"));
    }

    /// FR-108 P2 — the config starts at the configured size exactly, declares
    /// the reduced blanking its modelines carry (or Xorg drops the start mode
    /// and starts at the dummy's 2048x1536, with nothing named to restore to),
    /// and adds no input device.
    #[test]
    fn xorg_conf_starts_at_the_configured_size() {
        let c = xorg_conf(1920, 1080);
        assert!(c.contains(r#"Driver "dummy""#), "{c}");
        assert!(c.contains(&format!("VideoRam {XORG_VIDEO_RAM_KIB}")), "{c}");
        assert!(c.contains(r#"Option "ReducedBlanking" "true""#), "{c}");
        assert!(
            c.contains(r#"Modeline "roomler-1920x1080" 138.52 1920 1968 2000 2080 1080 1083 1088 1110 +hsync +vsync"#),
            "{c}"
        );
        assert!(c.contains(r#"Modes "roomler-1920x1080""#), "{c}");
        assert!(c.contains(r#"Option "AutoAddDevices" "false""#), "{c}");
        assert!(c.contains(r#"Option "BlankTime" "0""#), "{c}");
    }

    /// FR-108 P2 — Xorg's argv: its own config and an EMPTY config dir (no
    /// host `xorg.conf.d` snippet), loopback only, and nothing that blanks.
    #[test]
    fn xorg_args_isolate_and_never_blank() {
        let a = xorg_args(
            ":101",
            Path::new("/tmp/x/xorg.conf"),
            Path::new("/tmp/x/conf.d"),
            Path::new("/tmp/x/Xorg.log"),
        );
        assert_eq!(a.first().map(String::as_str), Some(":101"));
        let after = |flag: &str| {
            a.iter()
                .position(|s| s == flag)
                .and_then(|i| a.get(i + 1))
                .cloned()
        };
        assert_eq!(after("-config").as_deref(), Some("/tmp/x/xorg.conf"));
        assert_eq!(after("-configdir").as_deref(), Some("/tmp/x/conf.d"));
        assert_eq!(after("-nolisten").as_deref(), Some("tcp"));
        assert_eq!(
            after("-s").as_deref(),
            Some("0"),
            "-s 0 disables the screen saver"
        );
        for flag in ["-dpms", "-ac", "-noreset", "-novtswitch"] {
            assert!(a.iter().any(|s| s == flag), "{flag} missing from {a:?}");
        }
    }

    /// FR-108 P2 — Xorg with the dummy driver only when the real binary, the
    /// driver and `xrandr` are all there; the first binary found wins.
    #[test]
    fn xorg_dummy_needs_the_binary_the_driver_and_xrandr() {
        let have = |set: &'static [&'static str]| move |p: &str| set.contains(&p);
        let all: &'static [&'static str] = &[
            "/usr/lib/xorg/Xorg",
            "/usr/lib/xorg/modules/drivers/dummy_drv.so",
        ];
        assert_eq!(
            pick_xorg_dummy(have(all), true),
            Some(std::path::PathBuf::from("/usr/lib/xorg/Xorg"))
        );
        assert_eq!(
            pick_xorg_dummy(have(all), false),
            None,
            "no xrandr: no way to switch"
        );
        let fedora: &'static [&'static str] = &[
            "/usr/libexec/Xorg",
            "/usr/lib64/xorg/modules/drivers/dummy_drv.so",
        ];
        assert_eq!(
            pick_xorg_dummy(have(fedora), true),
            Some(std::path::PathBuf::from("/usr/libexec/Xorg"))
        );
        let no_driver: &'static [&'static str] = &["/usr/lib/xorg/Xorg"];
        assert_eq!(pick_xorg_dummy(have(no_driver), true), None);
        let wrapper_only: &'static [&'static str] = &[
            "/usr/bin/Xorg",
            "/usr/lib/xorg/modules/drivers/dummy_drv.so",
        ];
        assert_eq!(
            pick_xorg_dummy(have(wrapper_only), true),
            None,
            "the console-only wrapper is not the binary"
        );
    }

    /// FR-108 P2 — the kill switch is the one word, any case.
    #[test]
    fn the_server_kill_switch() {
        assert!(server_forced_xvfb(Some("xvfb")));
        assert!(server_forced_xvfb(Some(" XVFB ")));
        assert!(!server_forced_xvfb(Some("xorg")));
        assert!(!server_forced_xvfb(Some("")));
        assert!(!server_forced_xvfb(None));
    }

    #[test]
    fn parse_resolution_parses_and_falls_back() {
        assert_eq!(parse_resolution("1920x1080"), (1920, 1080));
        assert_eq!(parse_resolution("1280X720"), (1280, 720));
        assert_eq!(parse_resolution("garbage"), (1920, 1080));
        assert_eq!(parse_resolution("0x0"), (1920, 1080));
        assert_eq!(parse_resolution(""), (1920, 1080));
    }

    #[test]
    fn pick_display_returns_first_free_when_dir_absent() {
        // A dir that doesn't exist → no sockets → first candidate `:99`.
        assert_eq!(pick_display("/nonexistent/x11/dir/zzz"), ":99");
    }

    #[test]
    fn preflight_missing_binaries_names_apt_packages() {
        let cfg = Config {
            resolution: "1920x1080".into(),
            wm: "definitely-not-a-real-wm-binary-xyz".into(),
            startup: vec![],
        };
        let err = preflight(&cfg).unwrap_err().to_string();
        assert!(err.contains("apt install"), "err: {err}");
        assert!(
            err.contains("definitely-not-a-real-wm-binary-xyz"),
            "err: {err}"
        );
    }

    // ---- teardown (#1684) --------------------------------------------------

    /// A synthetic `/proc` entry. `starttime` plays no part in SELECTION, so
    /// a constant; the identity tests set it explicitly.
    #[cfg(target_os = "linux")]
    fn pi(pid: i32, ppid: i32, pgid: i32) -> ProcInfo {
        ProcInfo {
            pid,
            ppid,
            pgid,
            starttime: 1,
        }
    }

    /// The core of the fix: the SIGTERM-deaf `at-spi-bus-launcher` is a
    /// grandchild that `setsid`'d into its OWN process group, so the group net
    /// cannot see it — only the parent-link closure can. And the closure must
    /// walk DOWN from the desktop roots, never up into the daemon, so a sibling
    /// the daemon spawned for something else (an exec session) is never swept.
    #[cfg(target_os = "linux")]
    #[test]
    fn select_targets_reaches_a_setsid_grandchild_and_nothing_else() {
        let snap = [
            // The daemon itself, in its own group.
            pi(100, 1, 100),
            // Xvfb — the desktop group leader (pgid == pid).
            pi(200, 100, 200),
            // The WM / a startup app — still in the desktop group.
            pi(300, 200, 200),
            // at-spi-bus-launcher: a grandchild that setsid'd into its OWN
            // group (400), so pgid == 200 does NOT match it.
            pi(400, 300, 400),
            // An unrelated process.
            pi(500, 1, 500),
            // ANOTHER daemon child — an exec/PTY session, say — that the
            // desktop teardown must never touch.
            pi(600, 100, 600),
        ];
        let targets = select_targets(&snap, &[200], Some(200), 100);
        assert!(targets.contains(&200), "Xvfb");
        assert!(targets.contains(&300), "the WM/app");
        assert!(
            targets.contains(&400),
            "the setsid'd grandchild must be reached via the parent-link closure"
        );
        assert!(!targets.contains(&100), "never the daemon");
        assert!(!targets.contains(&500), "never an unrelated process");
        assert!(
            !targets.contains(&600),
            "never a non-desktop child of the daemon"
        );
        assert_eq!(targets.len(), 3, "{targets:?}");
    }

    /// A root that already exited (absent from the snapshot) is still targeted:
    /// signalling it is harmless (ESRCH) and it lets `reap` collect a zombie.
    #[cfg(target_os = "linux")]
    #[test]
    fn select_targets_keeps_roots_absent_from_the_snapshot() {
        let targets = select_targets(&[], &[7, 8], None, 999);
        assert!(targets.contains(&7) && targets.contains(&8));
    }

    /// Defensive: pid 0/1 and the daemon are removed even if a link points at
    /// them — a reparent to init must not turn into "signal init".
    #[cfg(target_os = "linux")]
    #[test]
    fn select_targets_never_signals_pid1_or_the_daemon() {
        let snap = [
            pi(1, 0, 1),
            pi(100, 1, 200), // daemon, sharing the group
            pi(200, 1, 200), // a root, ppid reparented to init
            pi(300, 200, 200),
        ];
        let targets = select_targets(&snap, &[200], Some(200), 100);
        assert!(!targets.contains(&1), "never pid 1");
        assert!(!targets.contains(&0), "never pid 0");
        assert!(!targets.contains(&100), "never the daemon");
        assert!(targets.contains(&200) && targets.contains(&300));
    }

    /// A `/proc/<pid>/stat` line for pid 1234 (`Xvfb`), started at tick
    /// 987654 — field 22, the 20th token after the comm's closing `)`.
    #[cfg(target_os = "linux")]
    const STAT_1234: &str = "1234 (Xvfb) S 1 1234 1234 0 -1 4194560 100 0 0 0 5 3 0 0 20 0 1 0 987654 12345 678 18446744073709551615 1 1 0 0 0 0 0 0 0 0 0 0 17 0 0 0 0 0 0 0 0 0 0 0 0 0 0";

    /// Identity is the starttime: equal ⇒ the same process; different ⇒ the pid
    /// was recycled; unreadable ⇒ never "the same" (when in doubt, don't signal).
    #[cfg(target_os = "linux")]
    #[test]
    fn same_process_compares_starttime_and_fails_safe() {
        assert_eq!(parse_stat(STAT_1234), Some(("S", 1, 1234, 987_654)));
        let info = ProcInfo {
            pid: 1234,
            ppid: 1,
            pgid: 1234,
            starttime: 987_654,
        };
        // The same stat.
        assert!(same_process(&info, STAT_1234));
        // A recycled pid: everything equal but a later starttime.
        let recycled = STAT_1234.replace(" 987654 ", " 987655 ");
        assert_ne!(recycled, STAT_1234, "the fixture must contain the field");
        assert!(!same_process(&info, &recycled));
        // Unparseable, in every way a read can go wrong.
        assert!(!same_process(&info, ""));
        assert!(!same_process(&info, "garbage"));
        assert!(!same_process(&info, "1234 (Xvfb) S 1 1234 1234 0")); // too short
        assert!(!same_process(
            &info,
            "1234 (Xvfb) S 1 1234 1234 0 -1 4194560 100 0 0 0 5 3 0 0 20 0 1 0 notanumber"
        ));
        // A comm with spaces and `)` in it is split on the LAST `)`.
        let evil = STAT_1234.replace("(Xvfb)", "(a) b) c)");
        assert!(same_process(&info, &evil));
        assert_eq!(parse_stat(&evil).map(|t| t.1), Some(1), "ppid still f4");
    }

    /// What `kill_tree_with` did, in order.
    #[cfg(target_os = "linux")]
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Ev {
        Signal(i32, i32),
        Killpg(i32, i32),
        /// `same_process_now` was asked about this pid.
        Identity(i32),
        Reap,
    }

    /// A scripted process table. `deaf` pids ignore SIGTERM (at-spi);
    /// `recycled` pids LOOK running but fail the identity check — the number
    /// now belongs to somebody else's process.
    #[cfg(target_os = "linux")]
    struct MockProcs {
        table: Vec<ProcInfo>,
        running: std::collections::BTreeSet<i32>,
        deaf: std::collections::BTreeSet<i32>,
        recycled: std::collections::BTreeSet<i32>,
        events: Vec<Ev>,
    }

    #[cfg(target_os = "linux")]
    impl MockProcs {
        fn new(table: &[ProcInfo], deaf: &[i32], recycled: &[i32]) -> Self {
            Self {
                table: table.to_vec(),
                running: table.iter().map(|p| p.pid).collect(),
                deaf: deaf.iter().copied().collect(),
                recycled: recycled.iter().copied().collect(),
                events: Vec::new(),
            }
        }
        fn deliver(&mut self, pid: i32, sig: i32) {
            if sig == libc::SIGKILL || !self.deaf.contains(&pid) {
                self.running.remove(&pid);
            }
        }
    }

    #[cfg(target_os = "linux")]
    impl Procs for MockProcs {
        fn snapshot(&mut self) -> Vec<ProcInfo> {
            // A dead process leaves `/proc` once its parent (or init) reaps it.
            let running = &self.running;
            self.table
                .iter()
                .filter(|p| running.contains(&p.pid))
                .copied()
                .collect()
        }
        fn is_running(&mut self, pid: i32) -> bool {
            self.running.contains(&pid)
        }
        fn same_process_now(&mut self, info: &ProcInfo) -> bool {
            self.events.push(Ev::Identity(info.pid));
            self.running.contains(&info.pid) && !self.recycled.contains(&info.pid)
        }
        fn signal(&mut self, pid: i32, sig: i32) {
            self.events.push(Ev::Signal(pid, sig));
            self.deliver(pid, sig);
        }
        fn killpg(&mut self, pgid: i32, sig: i32) {
            self.events.push(Ev::Killpg(pgid, sig));
            let members: Vec<i32> = self
                .table
                .iter()
                .filter(|p| p.pgid == pgid)
                .map(|p| p.pid)
                .collect();
            for m in members {
                self.deliver(m, sig);
            }
        }
        fn reap(&mut self, _roots: &[i32]) -> bool {
            self.events.push(Ev::Reap);
            true
        }
        fn sleep(&mut self, _d: Duration) {}
    }

    /// The field tree: Xvfb (root, group leader) → the WM → a SIGTERM-deaf
    /// grandchild that `setsid`'d into its own group.
    #[cfg(target_os = "linux")]
    fn desktop_tree() -> [ProcInfo; 3] {
        [pi(200, 7, 200), pi(300, 200, 200), pi(400, 300, 400)]
    }

    /// Rule 1 of `kill_tree_with`: every signal — both passes, both `killpg`s
    /// — is sent before ANY root is reaped, because reaping frees a pid (and,
    /// for Xvfb, the desktop's pgid) that a later signal would then hit
    /// recycled. Reaping inside the grace loop is exactly what the first cut
    /// of this code did. And rule 2: the SIGKILL of the non-root grandchild is
    /// preceded, immediately, by its identity check.
    #[cfg(target_os = "linux")]
    #[test]
    fn kill_tree_signals_everything_before_it_reaps_anything() {
        let mut m = MockProcs::new(&desktop_tree(), &[400], &[]);
        kill_tree_with(&mut m, &[200], Some(200), Duration::from_millis(30));
        let ev = &m.events;
        let first_reap = ev
            .iter()
            .position(|e| *e == Ev::Reap)
            .expect("the roots are reaped at the end");
        let last_signal = ev
            .iter()
            .rposition(|e| matches!(e, Ev::Signal(..) | Ev::Killpg(..)))
            .expect("something was signalled");
        assert!(
            last_signal < first_reap,
            "a reap ran before the last signal: {ev:?}"
        );
        assert_eq!(
            ev.iter().filter(|e| **e == Ev::Reap).count(),
            1,
            "reaped once, at the end: {ev:?}"
        );
        // The deaf grandchild needed SIGKILL; the others died on SIGTERM.
        let kill_400 = ev
            .iter()
            .position(|e| *e == Ev::Signal(400, libc::SIGKILL))
            .expect("the SIGTERM-deaf grandchild is SIGKILLed");
        assert!(!ev.contains(&Ev::Signal(200, libc::SIGKILL)), "{ev:?}");
        assert!(!ev.contains(&Ev::Signal(300, libc::SIGKILL)), "{ev:?}");
        // …and its identity was re-read RIGHT before that SIGKILL.
        assert_eq!(
            ev[kill_400 - 1],
            Ev::Identity(400),
            "identity check must immediately precede the kill: {ev:?}"
        );
        // Both group kills happened, each after the per-pid signals of its pass.
        assert!(ev.contains(&Ev::Killpg(200, libc::SIGTERM)), "{ev:?}");
        assert!(ev.contains(&Ev::Killpg(200, libc::SIGKILL)), "{ev:?}");
        assert!(m.running.is_empty(), "left running: {:?}", m.running);
    }

    /// Rule 2: a pid that is not our own child is signalled only while it is
    /// still the process the snapshot saw. Here 400's number has been recycled
    /// — it LOOKS running but fails the identity check — so it must not receive
    /// a single signal, TERM or KILL. Our own children (pids we hold unreaped,
    /// hence unrecyclable) are still torn down. systemd's own cgroup kill is the
    /// backstop for what we refuse to touch.
    #[cfg(target_os = "linux")]
    #[test]
    fn kill_tree_never_signals_a_recycled_pid() {
        let mut m = MockProcs::new(&desktop_tree(), &[400], &[400]);
        kill_tree_with(&mut m, &[200], Some(200), Duration::from_millis(30));
        let ev = &m.events;
        assert!(
            ev.contains(&Ev::Identity(400)),
            "identity was checked: {ev:?}"
        );
        assert!(
            !ev.iter().any(|e| matches!(e, Ev::Signal(400, _))),
            "a recycled pid was signalled: {ev:?}"
        );
        assert!(ev.contains(&Ev::Signal(200, libc::SIGTERM)), "{ev:?}");
        assert!(ev.contains(&Ev::Signal(300, libc::SIGTERM)), "{ev:?}");
        // Whoever holds 400 now is untouched.
        assert!(m.running.contains(&400), "{:?}", m.running);
    }

    /// End to end, with real syscalls: build the field failure — a daemon
    /// child, its child, and a SIGTERM-deaf grandchild that `setsid`s into its
    /// own session (as at-spi-bus-launcher does) — then run the teardown and
    /// prove the whole tree is gone within the bound. Before the fix, the
    /// grandchild survives every signal the daemon sent.
    #[cfg(target_os = "linux")]
    #[test]
    // The spawned `root` is reaped by `kill_tree`/`reap` (libc `waitpid`) rather
    // than `Child::wait`, and on the `setsid`-missing skip path it is killed via
    // its group — so the lint's "call `.wait()`" advice does not apply, and it
    // cannot see the `waitpid` we do call.
    #[allow(clippy::zombie_processes)]
    fn kill_tree_reaps_a_sigterm_deaf_setsid_grandchild() {
        use std::io::Write as _;

        let dir = std::env::temp_dir().join(format!(
            "roomler-vdesk-teardown-{}-{}",
            std::process::id(),
            line!()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let d = dir.display();

        // root → child subshell → grandchild. The grandchild `setsid`s (its
        // own session/group), traps SIGTERM, and loops — so only SIGKILL ends
        // it, exactly like the field host's at-spi-bus-launcher.
        let script = format!(
            "echo $$ > \"{d}/root.pid\"\n\
             (\n\
             echo $$ > \"{d}/child.pid\"\n\
             setsid sh -c 'echo $$ > \"{d}/gc.pid\"; trap \"\" TERM; while true; do sleep 1; done' &\n\
             sleep 300\n\
             ) &\n\
             sleep 300\n"
        );
        let script_path = dir.join("tree.sh");
        std::fs::File::create(&script_path)
            .unwrap()
            .write_all(script.as_bytes())
            .unwrap();

        let mut cmd = Command::new("sh");
        cmd.arg(&script_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        lead_new_group(&mut cmd);
        let root = cmd.spawn().expect("spawn the desktop-tree root");
        let root_pid = root.id() as i32;
        let pgid = group_of(&root);

        let read_pid = |name: &str| -> Option<i32> {
            std::fs::read_to_string(dir.join(name))
                .ok()
                .and_then(|s| s.trim().parse::<i32>().ok())
        };
        let (mut child, mut gc) = (None, None);
        let start = Instant::now();
        while start.elapsed() < Duration::from_secs(5) {
            child = read_pid("child.pid");
            gc = read_pid("gc.pid");
            if child.is_some() && gc.is_some() {
                break;
            }
            std::thread::sleep(Duration::from_millis(50));
        }

        let Some(gc) = gc else {
            // No `setsid` binary (a minimal host) ⇒ the grandchild never
            // formed. Tear down what we did spawn and skip — the pure
            // `select_targets` tests carry the closure proof without it.
            if let Some(g) = pgid {
                unsafe {
                    libc::killpg(g, libc::SIGKILL);
                }
            }
            let _ = std::fs::remove_dir_all(&dir);
            eprintln!("SKIP kill_tree_reaps_…: `setsid` unavailable; grandchild never formed");
            return;
        };
        let child = child.expect("child pid recorded once the grandchild is");

        assert!(
            is_running(gc),
            "the grandchild must be alive before teardown"
        );

        // The fix under test.
        kill_tree(&[root_pid], pgid, Duration::from_secs(3));

        let (root_alive, child_alive, gc_alive) =
            (is_running(root_pid), is_running(child), is_running(gc));

        // Belt-and-braces cleanup so a failing assertion never leaks the tree.
        if let Some(g) = pgid {
            unsafe {
                libc::killpg(g, libc::SIGKILL);
            }
        }
        RealProcs.signal(gc, libc::SIGKILL);
        RealProcs.reap(&[root_pid]);
        let _ = std::fs::remove_dir_all(&dir);

        assert!(!root_alive, "the root must be gone");
        assert!(!child_alive, "the child must be gone");
        assert!(
            !gc_alive,
            "the SIGTERM-deaf, setsid'd grandchild must be SIGKILLed within the bound"
        );
    }
}
