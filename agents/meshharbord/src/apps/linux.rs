// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Linux virtual-desktop backend: `wmctrl` (list/focus) + `tmux` (bash
//! sessions) + `xterm`. Shell-out only — no new crate — consistent with
//! how [`crate::virtual_desktop`] already spawns Xvfb/WM/apps.
//!
//! ## Session model (the flagship)
//! A bash "session" is a **tmux** session shown as an xterm attached to
//! it. This gives three properties a bare xterm can't:
//! * survives the agent restarting / the operator disconnecting (the
//!   tmux server outlives both);
//! * ssh-attachable (`tmux attach -t <name>` from a real login);
//! * one X window per session, so focus works.
//!
//! We launch our own windows with a known title
//! (`roomler:tmux:<session>` / `roomler:app:<key>`) so [`super::classify_title`]
//! can map a window back to its session/app without pid/xprop games.
//!
//! A tmux session with **no live xterm** (after an agent restart, or the
//! operator detached) still appears in the list with a synthetic
//! `tmux:<session>` window id; [`LinuxWm::focus`] special-cases that to
//! spawn a fresh attached xterm — so "attach to an existing bash
//! session" works within the 3-message protocol (no separate verb).

use std::collections::BTreeSet;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};

use anyhow::{Context, Result, bail};

use super::{
    Coverage, LaunchOutcome, ResolvedApp, WindowInfo, WindowManager, classify_title,
    next_tmux_session_name, parse_tmux_sessions, parse_wmctrl_list,
};
use super::{MissingTool, Unavailable};

/// Synthetic window-id prefix for a detached tmux session (no live X
/// window). `focus()` treats it as "attach", not "raise".
const DETACHED_PREFIX: &str = "tmux:";

/// Upper bound on concurrent tmux sessions a browser can spawn — bounds
/// resource use from a misbehaving/compromised controller.
const MAX_TMUX_SESSIONS: usize = 32;

/// How long to wait before re-listing to resolve a freshly-launched
/// window's id (best-effort; `None` on miss and the browser re-lists).
const LAUNCH_SETTLE: std::time::Duration = std::time::Duration::from_millis(250);

/// How to reach the desktop we manage.
///
/// FR-56 P1. Before this there was only a display string, which silently
/// encoded a second assumption: that the DAEMON owns the X server. That is
/// true in virtual-desktop mode and false everywhere else, and it is why
/// Remote Apps never engaged on a Wayland host — see [`discover`].
#[derive(Debug)]
pub enum Target {
    /// Virtual-desktop mode: the daemon started Xvfb and owns it, so commands
    /// run as the daemon with nothing but `DISPLAY`. Byte-for-byte the
    /// pre-FR-56 behaviour, and the only population using this today.
    Daemon { display: String },
    /// A logged-in user's session — X11, or Wayland whose compositor runs
    /// Xwayland (mutter does, even headless). Commands are **dropped to that
    /// account** and carry the session's X cookie.
    ///
    /// ⚠️ The privilege drop is not politeness. `launch` spawns a terminal and
    /// a tmux server; doing that as root on somebody's own desktop session
    /// would put a root shell on their screen and leave root-owned state in
    /// their runtime dir. The daemon owning Xvfb is the *only* case where
    /// running as the daemon is the right answer.
    Session {
        display: String,
        /// Whether the login session is Wayland — i.e. whether there are
        /// native Wayland windows that `wmctrl` structurally cannot see.
        /// Reported to the browser (FR-56 P2), never used to gate anything.
        wayland: bool,
        /// `None` is legal: an X server started without auth accepts anyone.
        /// ⚠️ But on a compositor-started Xwayland it is effectively required —
        /// without it every call dies `Authorization required, but no
        /// authorization protocol specified`, which is what `DISPLAY`-only did.
        xauthority: Option<PathBuf>,
        /// The account to drop to, by NAME (`getpwnam` gives the home dir and
        /// supplementary groups a uid alone cannot).
        user: String,
    },
}

pub struct LinuxWm {
    target: Target,
}

impl LinuxWm {
    pub fn new(target: Target) -> Self {
        Self { target }
    }

    /// Build a command aimed at the target desktop.
    ///
    /// ⚠️ Fallible on purpose. If the privilege drop cannot be installed the
    /// only safe outcome is to run NOTHING — silently falling back would run a
    /// user's terminal as root, which is the exact failure this exists to
    /// prevent. An infallible `cmd()` cannot express that.
    fn cmd(&self, program: &str) -> Result<Command> {
        let mut c = Command::new(program);
        match &self.target {
            Target::Daemon { display } => {
                c.env("DISPLAY", display);
            }
            Target::Session {
                display,
                xauthority,
                user,
                ..
            } => {
                c.env("DISPLAY", display);
                if let Some(xa) = xauthority {
                    c.env("XAUTHORITY", xa);
                }
                crate::exec::drop_to_std(&mut c, user)
                    .map_err(|e| anyhow::anyhow!("cannot run `{program}` as {user}: {e}"))?;
            }
        }
        Ok(c)
    }

    /// Run a helper and capture its output. A `NotFound` spawn error is
    /// rewritten into an actionable "install X" message.
    fn run_capture(&self, program: &str, args: &[&str], apt: &str) -> Result<Output> {
        self.cmd(program)?
            .args(args)
            .stdin(Stdio::null())
            .output()
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    anyhow::anyhow!(
                        "`{program}` not installed on the agent host (apt install {apt})"
                    )
                } else {
                    anyhow::Error::new(e).context(format!("running {program}"))
                }
            })
    }

    /// Spawn a detached, stdio-null child (an xterm / GUI app). The child
    /// keeps running after the handle drops (std, unlike tokio).
    fn spawn_detached(&self, program: &str, args: &[&str], apt: &str) -> Result<()> {
        self.cmd(program)?
            .args(args)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|e| {
                if e.kind() == std::io::ErrorKind::NotFound {
                    anyhow::anyhow!(
                        "`{program}` not installed on the agent host (apt install {apt})"
                    )
                } else {
                    anyhow::Error::new(e).context(format!("spawning {program}"))
                }
            })?;
        Ok(())
    }

    /// The active window's id (numeric), via `xprop -root
    /// _NET_ACTIVE_WINDOW`. Best-effort: `None` if xprop is missing or
    /// the property is unset.
    fn active_window(&self) -> Option<u64> {
        let out = self
            .run_capture("xprop", &["-root", "_NET_ACTIVE_WINDOW"], "x11-utils")
            .ok()?;
        let text = String::from_utf8_lossy(&out.stdout);
        // e.g. "_NET_ACTIVE_WINDOW(WINDOW): window id # 0x3400007"
        let hex = text.rsplit("0x").next()?.trim();
        u64::from_str_radix(hex.trim_start_matches("0x"), 16).ok()
    }

    /// tmux session names (empty when no server is running — tmux exits
    /// non-zero for that, which is NOT an error here).
    fn tmux_sessions(&self) -> Vec<String> {
        match self.run_capture("tmux", &["list-sessions", "-F", "#{session_name}"], "tmux") {
            Ok(out) => parse_tmux_sessions(&String::from_utf8_lossy(&out.stdout)),
            Err(_) => Vec::new(),
        }
    }

    /// Find a freshly-launched window's id by its exact raw title.
    fn window_id_by_title(&self, want_title: &str) -> Option<String> {
        let out = self.run_capture("wmctrl", &["-l"], "wmctrl").ok()?;
        parse_wmctrl_list(&String::from_utf8_lossy(&out.stdout))
            .into_iter()
            .find(|w| w.title == want_title)
            .map(|w| w.window_id)
    }
}

/// Is `program` runnable — i.e. would `Command::new(program)` find it?
///
/// ⚠️ Resolved against the **daemon's** `PATH` on purpose, because that is
/// what the spawn will use: [`crate::exec::drop_to_std`] changes the child's
/// uid from a `pre_exec` hook, long after the environment was inherited, so
/// the target user's login `PATH` never enters into it. Asking the question
/// any other way would answer about an environment the child never gets.
///
/// ⚠️ Best-effort in ONE direction: a hit means the file exists and carries an
/// execute bit, not that this user may run it (a restrictive ACL or a `noexec`
/// mount still fails at spawn). It is here to catch "the package is not
/// installed" — the case actually measured — and a wrong answer degrades to
/// today's behaviour, a clear error at click time.
fn on_path(program: &str) -> bool {
    on_path_in(program, std::env::var_os("PATH").as_deref())
}

/// [`on_path`] against an explicit `PATH` value.
///
/// ⚠️ The seam the tests use instead of rewriting the process-wide `PATH`.
/// libtest runs tests on parallel threads of ONE process, so a test that set
/// `PATH` to a scratch directory made every test spawning at that moment fail
/// `NotFound`: CI run 36476657197 lost 11 unrelated tests at once, every exec
/// test reading `shell "bash" is not installed on this device`.
fn on_path_in(program: &str, path: Option<&std::ffi::OsStr>) -> bool {
    use std::os::unix::fs::PermissionsExt;
    let Some(path) = path else {
        return false;
    };
    std::env::split_paths(path).any(|dir| {
        let candidate = dir.join(program);
        std::fs::metadata(&candidate)
            .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
            .unwrap_or(false)
    })
}

/// Every helper this backend shells out to, with what it costs to lack it.
///
/// ⚠️ `wmctrl` is deliberately NOT here: without it there is no backend at all
/// (`list` and `focus` ARE wmctrl), so its absence has to surface as a plain
/// error from the call itself, not as a partial capability in a reply that
/// otherwise reads like success.
const HELPERS: &[MissingTool] = &[
    MissingTool {
        tool: "tmux",
        blocks: "persistent shell sessions (the ones that survive an agent restart)",
        install: "apt install tmux",
    },
    MissingTool {
        tool: "xterm",
        blocks: "launching shells and terminal apps (GUI apps still launch)",
        install: "apt install xterm",
    },
];

impl LinuxWm {
    /// [`WindowManager::coverage`], with `present` answering whether a helper
    /// is installed — [`on_path`] in production. The same seam as
    /// [`on_path_in`], for the same reason: a test can say "nothing is
    /// installed" without emptying the `PATH` every other test spawns through.
    fn coverage_with(&self, present: impl Fn(&str) -> bool) -> Coverage {
        let wayland = matches!(&self.target, Target::Session { wayland: true, .. });
        Coverage {
            sources: vec!["x11"],
            unlisted: wayland.then(|| {
                "native Wayland windows: this compositor exposes no protocol to enumerate \
                 them (X11/Xwayland windows are listed)"
                    .to_string()
            }),
            // FR-56 P5 — probed per call, never cached. A host can gain `tmux`
            // at any moment, and FR-45 already learned that a cached
            // capability answers about the wrong start order.
            missing_tools: HELPERS
                .iter()
                .filter(|h| !present(h.tool))
                .cloned()
                .collect(),
        }
    }
}

impl WindowManager for LinuxWm {
    /// FR-56 P2 — what this listing covers.
    ///
    /// The X11 backend sees Xwayland clients and is **structurally blind** to
    /// native Wayland windows: measured on a GNOME Wayland session, `foot` and
    /// `gnome-text-editor` were running and simply absent from `wmctrl -l`.
    ///
    /// ⚠️ Reporting that is the whole point. Without it the browser gets a
    /// SHORTER list that looks exactly like a quiet desktop, and there is
    /// nothing anywhere saying a second source exists. Enumerating native
    /// Wayland windows needs a compositor protocol (`zwlr_foreign_toplevel_
    /// management_v1` on wlroots) that GNOME/mutter deliberately does not
    /// expose — so on GNOME this gap is permanent, not a TODO.
    fn coverage(&self) -> Coverage {
        self.coverage_with(on_path)
    }

    fn list(&self) -> Result<Vec<WindowInfo>> {
        // Live X windows.
        let out = self.run_capture("wmctrl", &["-l"], "wmctrl")?;
        // ⚠️ The status check is load-bearing, and it was missing. `wmctrl -l`
        // against a display it cannot open writes NOTHING to stdout and exits
        // non-zero, so parsing stdout regardless turned "I could not reach the
        // desktop" into `Ok(vec![])` — *no windows*, which is a different
        // claim and a reassuring one. Measured under FR-56 P1: pointing the
        // daemon at `:99` (no X server there) reported `windows: 0` rather
        // than an error. `focus` and `tmux new-session` already check; only
        // this one did not, and discovery makes it matter — the display is now
        // found rather than owned, so it CAN go stale (a compositor restart
        // invalidates the cookie) where an Xvfb the daemon started could not.
        if !out.status.success() {
            bail!(
                "wmctrl could not read the window list from {}: {}",
                match &self.target {
                    Target::Daemon { display } => display.clone(),
                    Target::Session { display, .. } => display.clone(),
                },
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        let raw = parse_wmctrl_list(&String::from_utf8_lossy(&out.stdout));
        let active = self.active_window();

        let mut windows = Vec::new();
        let mut attached_sessions: BTreeSet<String> = BTreeSet::new();
        for w in raw {
            let c = classify_title(&w.title);
            if let Some(s) = &c.session {
                attached_sessions.insert(s.clone());
            }
            let focused = active
                .zip(parse_hex(&w.window_id))
                .is_some_and(|(a, id)| a == id);
            windows.push(WindowInfo {
                window_id: w.window_id,
                title: c.title,
                app_key: c.app_key,
                session: c.session,
                focused,
            });
        }

        // Detached tmux sessions (no live xterm): show them so the
        // operator can re-attach. Synthetic id → focus() spawns an xterm.
        for s in self.tmux_sessions() {
            if attached_sessions.contains(&s) {
                continue;
            }
            windows.push(WindowInfo {
                window_id: format!("{DETACHED_PREFIX}{s}"),
                title: format!("Terminal ({s}) — detached"),
                app_key: None,
                session: Some(s),
                focused: false,
            });
        }

        Ok(windows)
    }

    fn focus(&self, window_id: &str) -> Result<()> {
        // Detached tmux session → attach (spawn a fresh xterm).
        if let Some(session) = window_id.strip_prefix(DETACHED_PREFIX) {
            if !is_safe_session(session) {
                bail!("invalid session name");
            }
            let title = format!("roomler:tmux:{session}");
            self.spawn_detached(
                "xterm",
                &["-T", title.as_str(), "-e", "tmux", "attach", "-t", session],
                "xterm",
            )
            .with_context(|| format!("attaching to tmux session {session}"))?;
            return Ok(());
        }

        // Live window → raise. Guard the id shape so a malformed arg
        // can't be interpreted as a wmctrl flag.
        if parse_hex(window_id).is_none() {
            bail!("invalid window id");
        }
        let out = self.run_capture("wmctrl", &["-i", "-a", window_id], "wmctrl")?;
        if !out.status.success() {
            bail!(
                "wmctrl could not focus {window_id}: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Ok(())
    }

    fn launch(&self, app: &ResolvedApp) -> Result<LaunchOutcome> {
        if app.command.is_empty() {
            bail!("empty command");
        }

        if app.tmux {
            let existing = self.tmux_sessions();
            if existing.len() >= MAX_TMUX_SESSIONS {
                bail!("too many sessions ({MAX_TMUX_SESSIONS} max) — close some first");
            }
            let session = next_tmux_session_name(&existing);

            // Create the detached session running the configured shell.
            let mut new_args: Vec<&str> = vec!["new-session", "-d", "-s", session.as_str()];
            new_args.extend(app.command.iter().map(String::as_str));
            let created = self.run_capture("tmux", &new_args, "tmux")?;
            if !created.status.success() {
                bail!(
                    "tmux new-session failed: {}",
                    String::from_utf8_lossy(&created.stderr).trim()
                );
            }

            // Attach it in an xterm titled by our convention.
            let title = format!("roomler:tmux:{session}");
            self.spawn_detached(
                "xterm",
                &[
                    "-T",
                    title.as_str(),
                    "-e",
                    "tmux",
                    "attach",
                    "-t",
                    session.as_str(),
                ],
                "xterm",
            )?;

            std::thread::sleep(LAUNCH_SETTLE);
            return Ok(LaunchOutcome {
                window_id: self.window_id_by_title(&title),
                session: Some(session),
            });
        }

        if app.terminal {
            // TUI app in an xterm titled by our convention.
            let title = format!("roomler:app:{}", app.key);
            let mut args: Vec<&str> = vec!["-T", title.as_str(), "-e"];
            args.extend(app.command.iter().map(String::as_str));
            self.spawn_detached("xterm", &args, "xterm")?;
            std::thread::sleep(LAUNCH_SETTLE);
            return Ok(LaunchOutcome {
                window_id: self.window_id_by_title(&title),
                session: None,
            });
        }

        // GUI app: run the command directly; it sets its own window title.
        let (program, rest) = app.command.split_first().expect("non-empty checked above");
        let rest: Vec<&str> = rest.iter().map(String::as_str).collect();
        self.spawn_detached(program, &rest, program)?;
        Ok(LaunchOutcome::default())
    }
}

/// Parse an X11 window id (`0x03400007`) to a number for comparison.
fn parse_hex(id: &str) -> Option<u64> {
    let h = id.strip_prefix("0x").or_else(|| id.strip_prefix("0X"))?;
    if h.is_empty() || !h.chars().all(|c| c.is_ascii_hexdigit()) {
        return None;
    }
    u64::from_str_radix(h, 16).ok()
}

/// tmux session names we generate are `s<N>`; a re-attach target must
/// look like a plain session token (defence-in-depth against a crafted
/// `window_id` reaching a shell-free `tmux attach -t`).
fn is_safe_session(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 64
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
}

/// Work out how to reach a desktop on this host, or say why we cannot.
///
/// FR-56 P1. The old gate was `env::var_os("DISPLAY").is_some()` **on the
/// daemon**, which is only ever true in virtual-desktop mode — so on a Wayland
/// host Remote Apps did not fail, it never engaged.
///
/// Order is deliberate:
///
/// 1. **The daemon's own `DISPLAY`** wins. That is Xvfb mode, it is the only
///    population using this feature today, and it must stay byte-for-byte
///    unchanged — a "smarter" probe that reordered this would change behaviour
///    for the one set of hosts already relying on it.
/// 2. Otherwise, whoever is at the screen ([`crate::companion::graphical_session`],
///    already built for FR-27's consent prompt and FR-45's capture helper).
///    A Wayland session counts: mutter runs **Xwayland** even headless, so X11
///    tooling reaches its windows.
///
/// ⚠️ Candidates are **verified, not guessed**: each `DISPLAY`+cookie pair is
/// tried against `wmctrl -m` and the first that answers wins. `loginctl` does
/// not report a `Display=` for every Wayland session, so a guess of `:0` is
/// unavoidable — but an unverified guess would surface later as a confusing
/// "no windows" instead of an honest "no desktop".
///
/// FR-56 AC10: the `Err` is the REASON, and it rides the wire. This used to
/// return `Option`, which threw away three different answers — no session, no
/// X display, cannot run as the owner — on the way to one silent `None`.
pub fn discover() -> Result<Target, Unavailable> {
    if let Some(display) = std::env::var_os("DISPLAY").and_then(|d| d.into_string().ok()) {
        // Virtual-desktop mode. Unchanged, including running as the daemon:
        // the daemon started that Xvfb and owns it.
        return Ok(Target::Daemon { display });
    }
    discover_with(
        crate::companion::graphical_session().map_err(|e| format!("{e:#}")),
        probe,
    )
}

/// The session arm of [`discover`] with its two inputs injected — what
/// `loginctl` said (or why it said nothing), and what `wmctrl -m` answers per
/// candidate. The unit-test seam: the refusal arms below are decisions, and a
/// decision that can only be exercised on a host with a real login session is
/// one nobody re-checks.
fn discover_with(
    sess: Result<crate::companion::GraphicalSession, String>,
    probe: impl Fn(&Target) -> Probe,
) -> Result<Target, Unavailable> {
    let sess = match sess {
        Ok(s) => s,
        // This used to be `.ok()?`, which discarded the sentence
        // `graphical_session` composes ("no active graphical session — nobody
        // is at this machine's screen") and left the hello silent with nothing
        // anywhere saying why.
        Err(detail) => return refused(Unavailable::NoSession { detail }),
    };
    let xauthority = find_xauthority(sess.uid);
    // loginctl reports `Display=` for X11 sessions and often not for Wayland
    // ones; `:0` is what a compositor-started Xwayland almost always takes.
    let mut candidates: Vec<String> = Vec::new();
    if let Some(d) = sess.display.clone() {
        candidates.push(d);
    }
    for d in [":0", ":1"] {
        if !candidates.iter().any(|c| c == d) {
            candidates.push(d.to_string());
        }
    }

    for candidate in &candidates {
        let target = Target::Session {
            display: candidate.clone(),
            wayland: sess.wayland_display.is_some(),
            xauthority: xauthority.clone(),
            user: sess.name.clone(),
        };
        match probe(&target) {
            Probe::Answered => {
                // ⚠️ NOT `%display`: tracing's `%x` shorthand expands through
                // its own `field::display` helper, so a local named `display`
                // makes the macro resolve the FUNCTION instead — and rustc
                // 1.95 ICEs while rendering that error rather than printing
                // it (`--message-format=short` shows it).
                tracing::info!(
                    display = %candidate,
                    user = %sess.name,
                    xauthority = ?xauthority,
                    "apps: found a usable desktop in the user's session"
                );
                return Ok(target);
            }
            // Until AC10 this returned the target anyway, so the "install
            // wmctrl" message could reach the operator through the list
            // error — which also advertised `list` on a host that cannot
            // list. The reason now has its own lane, so the hello stays
            // honest and the message still arrives.
            Probe::ToolMissing => {
                return refused(Unavailable::ToolMissing {
                    tool: "wmctrl",
                    install: "apt install wmctrl",
                });
            }
            // Until AC10 this was folded into `NoDisplay`: a failed privilege
            // drop (an account `getpwnam` cannot resolve, a `setuid` refused)
            // was retried against the next display and then reported as "no
            // Xwayland" — a wrong answer that sent the operator to look at the
            // compositor. Nothing about the next display changes it, so stop.
            Probe::CannotRun(detail) => {
                return refused(Unavailable::CannotRunAs {
                    user: sess.name.clone(),
                    detail,
                });
            }
            Probe::NoDisplay => continue,
        }
    }
    refused(Unavailable::NoXDisplay {
        user: sess.name,
        tried: candidates,
    })
}

/// One log line per refusal, at `debug!` because on a headless server this
/// is the normal state and runs on every boot (the hello asks). The reason
/// reaches the operator through the reply and `roomlerd apps-probe` — the
/// point of AC10 is that the log is no longer the only place it lives.
fn refused(why: Unavailable) -> Result<Target, Unavailable> {
    tracing::debug!(
        code = why.code(),
        reason = %why.reason(),
        "apps: not available on this host"
    );
    Err(why)
}

/// Outcome of poking a candidate desktop.
enum Probe {
    /// An X server answered — this target is usable.
    Answered,
    /// `wmctrl` is not installed. Says nothing about the display.
    ToolMissing,
    /// The command could not be RUN — the privilege drop could not be
    /// installed, or the spawn failed for a reason other than "not found".
    /// Says nothing about the display either, and trying the next one cannot
    /// help.
    CannotRun(String),
    /// `wmctrl` ran and could not open that display.
    NoDisplay,
}

/// Try `wmctrl -m` against a candidate. Doubles as the dependency check,
/// because `wmctrl` is what the whole backend runs on.
fn probe(target: &Target) -> Probe {
    let wm = LinuxWm::new(match target {
        Target::Daemon { display } => Target::Daemon {
            display: display.clone(),
        },
        Target::Session {
            display,
            wayland,
            xauthority,
            user,
        } => Target::Session {
            display: display.clone(),
            wayland: *wayland,
            xauthority: xauthority.clone(),
            user: user.clone(),
        },
    });
    let mut cmd = match wm.cmd("wmctrl") {
        Ok(c) => c,
        Err(e) => return Probe::CannotRun(format!("{e:#}")),
    };
    match cmd
        .arg("-m")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
    {
        Ok(st) if st.success() => Probe::Answered,
        Ok(_) => Probe::NoDisplay,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Probe::ToolMissing,
        Err(e) => Probe::CannotRun(format!("spawning wmctrl: {e}")),
    }
}

/// Where a session's X cookie lives.
///
/// ⚠️ Measured, not assumed: with `DISPLAY` alone and no cookie every call
/// dies `Authorization required, but no authorization protocol specified` —
/// which is precisely what the pre-FR-56 code did, since `linux.rs` set
/// `DISPLAY` and nothing else. The compositor-generated name is a glob
/// (`.mutter-Xwaylandauth.XXXXXX`), so the directory is scanned rather than a
/// path guessed.
pub(crate) fn find_xauthority(uid: u32) -> Option<PathBuf> {
    let run = PathBuf::from(format!("/run/user/{uid}"));
    // Newest first: a compositor restart leaves the old cookie behind, and the
    // stale one authorises nothing.
    let mut mutter: Vec<(std::time::SystemTime, PathBuf)> = std::fs::read_dir(&run)
        .ok()?
        .flatten()
        .filter(|e| {
            e.file_name()
                .to_string_lossy()
                .starts_with(".mutter-Xwaylandauth")
        })
        .filter_map(|e| {
            let m = e.metadata().ok()?.modified().ok()?;
            Some((m, e.path()))
        })
        .collect();
    mutter.sort_by_key(|(modified, _)| std::cmp::Reverse(*modified));
    if let Some((_, path)) = mutter.into_iter().next() {
        return Some(path);
    }
    // GDM's X11 sessions, then the classic home-directory cookie.
    [run.join("gdm/Xauthority"), run.join("Xauthority")]
        .into_iter()
        .find(|c| c.is_file())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// FR-56 P5. `on_path` must answer about the DAEMON's `PATH`, since that
    /// is what the spawned child inherits — the uid change happens later, in a
    /// `pre_exec` hook, and never touches the environment.
    ///
    /// ⚠️ Asserted against a real directory rather than a mock, because the
    /// bug being prevented is not "the logic is wrong" but "we asked the wrong
    /// environment": a probe that consults the target user's login `PATH`
    /// would pass every unit test and still disagree with the spawn.
    ///
    /// ⚠️ And asserted in a CHILD process: this test binary, re-run with
    /// `PATH` set for that process alone. This test used to set the parent's
    /// `PATH` instead, which failed every test that spawned while it held the
    /// scratch value (see [`on_path_in`]). The logic runs here, through
    /// `on_path_in`; only "reads the process's own `PATH`" needs the child.
    #[test]
    fn on_path_answers_about_the_daemons_own_path() {
        const CHILD: &str = "ROOMLERD_TEST_ON_PATH_CHILD";
        const PROBES: [&str; 3] = [
            "roomler-p5-probe",
            "roomler-p5-notexec",
            "roomler-p5-does-not-exist",
        ];
        const EXPECT: [(bool, &str); 3] = [
            (true, "an executable file on PATH must be found"),
            (
                false,
                "a NON-executable file must not count: `Command::spawn` would fail on it, \
                 so reporting it as present would restore the very lie this probe removes",
            ),
            (false, "an absent binary must not be found"),
        ];
        // In the child: answer with the real `on_path`, against the only PATH
        // this process was given. stderr, because libtest writes its own
        // progress to stdout.
        if std::env::var_os(CHILD).is_some() {
            for p in PROBES {
                eprintln!("{CHILD} {p}={}", on_path(p));
            }
            return;
        }

        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("roomler-p5-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let exe = dir.join("roomler-p5-probe");
        std::fs::write(&exe, b"#!/bin/sh\ntrue\n").unwrap();
        std::fs::set_permissions(&exe, std::fs::Permissions::from_mode(0o755)).unwrap();
        let plain = dir.join("roomler-p5-notexec");
        std::fs::write(&plain, b"not executable").unwrap();
        std::fs::set_permissions(&plain, std::fs::Permissions::from_mode(0o644)).unwrap();

        let here = PROBES.map(|p| on_path_in(p, Some(dir.as_os_str())));

        let name = format!(
            "{}::on_path_answers_about_the_daemons_own_path",
            module_path!()
                .split_once("::")
                .map_or(module_path!(), |(_, rest)| rest)
        );
        let out = std::process::Command::new(std::env::current_exe().unwrap())
            .args([name.as_str(), "--exact", "--nocapture", "--test-threads=1"])
            .env("PATH", &dir)
            .env(CHILD, "1")
            .output()
            .expect("re-run this test binary as the child");
        let _ = std::fs::remove_dir_all(&dir);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success(), "the child failed:\n{stderr}");
        // `None` = the child never answered: its test name matched nothing, so
        // it ran nothing and exited 0. That must fail, not pass silently.
        let child = PROBES.map(|p| {
            let key = format!("{CHILD} {p}=");
            stderr
                .lines()
                .find_map(|l| l.split_once(key.as_str()))
                .map(|(_, v)| v.trim() == "true")
        });

        for (i, (want, why)) in EXPECT.into_iter().enumerate() {
            assert_eq!(here[i], want, "on_path_in({}): {why}", PROBES[i]);
            assert_eq!(
                child[i],
                Some(want),
                "on_path({}) in a process whose PATH is the scratch dir: {why}\n\
                 child stderr:\n{stderr}",
                PROBES[i]
            );
        }
    }

    /// FR-56 P5. The reply must name a missing helper, because `supported:
    /// true` was measured to be a lie: on a GNOME Wayland host with no `tmux`
    /// the panel reported the feature supported, offered the button, and only
    /// failed once somebody clicked it.
    ///
    /// ⚠️ The assertion is on the SHAPE of every entry, not just that the list
    /// is non-empty. A `MissingTool` whose `install` were blank would still
    /// satisfy "we reported something" while telling the operator nothing they
    /// can act on — and an unactionable warning beside a broken button is
    /// barely better than the silence it replaced.
    #[test]
    fn coverage_names_helpers_this_host_does_not_have() {
        // "Nothing is installed", said through the seam rather than by
        // emptying the process-wide PATH (see `on_path_in`).
        let cov = LinuxWm::new(Target::Daemon {
            display: ":99".into(),
        })
        .coverage_with(|_| false);

        assert_eq!(
            cov.missing_tools.len(),
            HELPERS.len(),
            "with nothing installed every helper is missing"
        );
        for t in &cov.missing_tools {
            assert!(!t.tool.is_empty());
            assert!(
                !t.blocks.is_empty(),
                "{}: must say what stops working, or the operator cannot judge whether \
                 to care",
                t.tool
            );
            assert!(
                t.install.contains("install"),
                "{}: must say how to fix it — an unactionable warning beside a broken \
                 button is barely better than the silence it replaced",
                t.tool
            );
        }
    }

    #[test]
    fn parse_hex_accepts_x11_ids() {
        assert_eq!(parse_hex("0x03400007"), Some(0x03400007));
        assert_eq!(parse_hex("0x3400007"), Some(0x3400007));
        assert!(parse_hex("tmux:main").is_none());
        assert!(parse_hex("0x").is_none());
        assert!(parse_hex("0xZZ").is_none());
        assert!(parse_hex("garbage").is_none());
    }

    /// FR-56 P2. A Wayland session MUST declare that native Wayland windows
    /// were not enumerated; an X11/Xvfb one must not, because there X11 is
    /// everything and a caveat would be noise.
    ///
    /// ⚠️ This is the `Some([])` vs `None` distinction on its fourth surface
    /// here: an empty list and an unenumerable source are different facts, and
    /// only the reply can tell them apart. Without `unlisted` the browser
    /// receives a shorter list that looks exactly like a quiet desktop.
    #[test]
    fn coverage_declares_what_x11_cannot_see() {
        let wayland = LinuxWm::new(Target::Session {
            display: ":0".into(),
            wayland: true,
            xauthority: None,
            user: "someone".into(),
        });
        let cov = wayland.coverage();
        assert_eq!(cov.sources, vec!["x11"]);
        let why = cov
            .unlisted
            .expect("a Wayland session must name the source it could not enumerate");
        assert!(why.contains("native Wayland"), "{why}");

        // Xvfb / a real X11 session: X11 IS the whole desktop.
        for t in [
            Target::Daemon {
                display: ":99".into(),
            },
            Target::Session {
                display: ":0".into(),
                wayland: false,
                xauthority: None,
                user: "someone".into(),
            },
        ] {
            let cov = LinuxWm::new(t).coverage();
            assert_eq!(cov.sources, vec!["x11"]);
            assert!(
                cov.unlisted.is_none(),
                "an X11 desktop has no second source to caveat"
            );
        }
    }

    #[test]
    fn safe_session_guard() {
        assert!(is_safe_session("s1"));
        assert!(is_safe_session("main"));
        assert!(is_safe_session("deploy-2"));
        assert!(!is_safe_session(""));
        assert!(!is_safe_session("a b"));
        assert!(!is_safe_session("a;rm -rf"));
        assert!(!is_safe_session(&"x".repeat(65)));
    }

    // ── FR-56 AC10 (review of #1667) — the refusal arms of `discover`, driven
    // through the `discover_with` seam with a scripted `wmctrl -m`. Each test
    // is red with its arm reverted to the pre-P6 behaviour (recorded in the
    // PR): ToolMissing → `Ok(target)`, CannotRun → `continue`, NoSession →
    // an empty detail.

    use std::cell::RefCell;

    /// A login session as `loginctl` would report it. The uid is one no host
    /// has, so `find_xauthority` finds no runtime dir and carries no cookie.
    fn session(display: Option<&str>, wayland: bool) -> crate::companion::GraphicalSession {
        crate::companion::GraphicalSession {
            uid: u32::MAX - 7,
            name: "someone".to_string(),
            display: display.map(str::to_string),
            wayland_display: wayland.then(|| "wayland-0".to_string()),
        }
    }

    fn display_of(t: &Target) -> String {
        match t {
            Target::Daemon { display } | Target::Session { display, .. } => display.clone(),
        }
    }

    #[test]
    fn no_session_keeps_the_sentence_and_never_probes() {
        let probes = RefCell::new(0u32);
        let sentence = "no active graphical session — nobody is at this machine's screen";
        let out = discover_with(Err(sentence.to_string()), |_| {
            *probes.borrow_mut() += 1;
            Probe::Answered
        });
        match out {
            Err(Unavailable::NoSession { detail }) => {
                assert!(
                    detail.contains("nobody is at this machine's screen"),
                    "{detail}"
                );
                assert!(
                    Unavailable::NoSession { detail }
                        .reason()
                        .contains("nobody is at"),
                    "the sentence must survive into the wire reason"
                );
            }
            other => panic!("expected NoSession, got {other:?}"),
        }
        assert_eq!(*probes.borrow(), 0, "nothing to probe without a session");
    }

    #[test]
    fn wmctrl_missing_on_the_first_candidate_refuses_at_once() {
        let probes = RefCell::new(0u32);
        let out = discover_with(Ok(session(Some(":5"), true)), |_| {
            *probes.borrow_mut() += 1;
            Probe::ToolMissing
        });
        match out {
            Err(Unavailable::ToolMissing { tool, install }) => {
                assert_eq!(tool, "wmctrl");
                assert!(install.contains("install"), "{install}");
            }
            other => panic!("expected ToolMissing, got {other:?}"),
        }
        // A missing binary says nothing about a display, and the next display
        // cannot install it: one probe, then the refusal.
        assert_eq!(*probes.borrow(), 1);
    }

    #[test]
    fn a_failed_privilege_drop_stops_at_the_first_candidate() {
        let tried: RefCell<Vec<String>> = RefCell::new(Vec::new());
        let out = discover_with(Ok(session(None, false)), |t| {
            tried.borrow_mut().push(display_of(t));
            Probe::CannotRun("setuid refused".to_string())
        });
        match out {
            Err(Unavailable::CannotRunAs { user, detail }) => {
                assert_eq!(user, "someone");
                assert_eq!(detail, "setuid refused");
            }
            other => panic!("expected CannotRunAs, got {other:?}"),
        }
        // Pre-P6 this was folded into NoDisplay: `:1` was tried next and the
        // answer came back as "no Xwayland". The account has not changed
        // between displays, so the walk must stop here.
        assert_eq!(*tried.borrow(), vec![":0".to_string()]);
    }

    #[test]
    fn no_x_display_walks_every_candidate_then_names_them() {
        let tried: RefCell<Vec<String>> = RefCell::new(Vec::new());
        let out = discover_with(Ok(session(Some(":7"), true)), |t| {
            tried.borrow_mut().push(display_of(t));
            Probe::NoDisplay
        });
        let want = vec![":7".to_string(), ":0".to_string(), ":1".to_string()];
        assert_eq!(
            *tried.borrow(),
            want,
            "loginctl's Display= first, then the guesses"
        );
        match out {
            Err(Unavailable::NoXDisplay { user, tried }) => {
                assert_eq!(user, "someone");
                assert_eq!(tried, want, "the reply names what was tried");
            }
            other => panic!("expected NoXDisplay, got {other:?}"),
        }
    }

    #[test]
    fn the_first_answering_candidate_wins_as_the_session_owner() {
        let out = discover_with(Ok(session(None, true)), |t| {
            if display_of(t) == ":1" {
                Probe::Answered
            } else {
                Probe::NoDisplay
            }
        });
        match out {
            Ok(Target::Session {
                display,
                wayland,
                user,
                xauthority,
            }) => {
                assert_eq!(display, ":1");
                assert!(wayland, "a Wayland session is reported as one (P2)");
                assert_eq!(
                    user, "someone",
                    "commands run as the session's owner, never root"
                );
                assert!(xauthority.is_none(), "no runtime dir for a uid nobody has");
            }
            other => panic!("expected a Session target on :1, got {other:?}"),
        }
    }
}
