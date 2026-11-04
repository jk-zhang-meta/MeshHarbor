// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-92 P9 — keep busy's two questions to a GNOME session, asked from
//! INSIDE it.
//!
//! The root daemon is not in the person's session: their session bus checks
//! `SO_PEERCRED`, so Mutter can only be asked by a child running AS them —
//! the same `portal-helper` subcommand, session lookup and privilege drop
//! FR-45 uses (`capture::portal::helper::spawn_child`), with `--keep-busy`.
//! The child answers one line per question for as long as the daemon keeps
//! its stdin open, and exits when it closes:
//!
//! * `idle` → `org.gnome.Mutter.IdleMonitor.GetIdletime`: milliseconds since
//!   the session's last input of any kind — the clock GNOME's own screen
//!   lock and every "Away" status read;
//! * `geom` → `org.gnome.Mutter.DisplayConfig.GetCurrentState`, reduced to
//!   the monitors in the coordinates an absolute pointing device is mapped
//!   onto ([`super::gnome::layout`]).
//!
//! It reads no input and sends none: the moves go through the input
//! arbiter's uinput device, like a controller's.

use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::process::{Child, ChildStdin};
use std::sync::mpsc::{Receiver, RecvTimeoutError};
use std::time::{Duration, Instant};

use zbus::zvariant::{OwnedValue, Value};

use super::gnome::{self, Geometry, LogicalIn, MARK, ModeIn, Reply};

const IDLE_BUS: &str = "org.gnome.Mutter.IdleMonitor";
const IDLE_PATH: &str = "/org/gnome/Mutter/IdleMonitor/Core";
const IDLE_IFACE: &str = "org.gnome.Mutter.IdleMonitor";
const DISPLAY_BUS: &str = "org.gnome.Mutter.DisplayConfig";
const DISPLAY_PATH: &str = "/org/gnome/Mutter/DisplayConfig";
const DISPLAY_IFACE: &str = "org.gnome.Mutter.DisplayConfig";
/// A helper asked nothing for this long exits (the daemon notices and starts
/// another when it needs one).
const HELPER_IDLE_EXIT: Duration = Duration::from_secs(60);

// ── The child: `roomlerd portal-helper --keep-busy`, run AS the person ─────

/// The helper's body. ⚠️ zbus's blocking API panics inside a tokio runtime,
/// and the subcommand is reached from `#[tokio::main]`, so the D-Bus work
/// runs on a plain thread (the rule `capture::portal::mutter` follows).
pub fn serve() {
    match std::thread::Builder::new()
        .name("kb-session-helper".into())
        .spawn(serve_blocking)
    {
        Ok(worker) => {
            let _ = worker.join();
        }
        Err(e) => println!("{MARK}err spawn {e}"),
    }
}

fn serve_blocking() {
    let mut out = std::io::stdout().lock();
    let mut say = move |line: String| {
        let _ = writeln!(out, "{MARK}{line}");
        let _ = out.flush();
    };
    let conn = match zbus::blocking::Connection::session() {
        Ok(c) => c,
        Err(e) => {
            say(format!("err bus {e}"));
            return;
        }
    };
    let idle = zbus::blocking::Proxy::new(&conn, IDLE_BUS, IDLE_PATH, IDLE_IFACE).ok();
    // A proxy builds happily for a name nobody owns: ASK once, so the hello
    // reports what really answers.
    let idle_ok = idle.as_ref().is_some_and(|p| idle_ms(p).is_ok());
    let geom_ok = geometry(&conn).is_ok();
    say(format!(
        "hello idle={} geom={}",
        u8::from(idle_ok),
        u8::from(geom_ok)
    ));
    // stdin on its own thread, so a helper nobody asks anything goes away by
    // itself: keep busy turned off, or the screen locked — the daemon starts
    // a new one when it needs one.
    let (tx, rx) = std::sync::mpsc::channel::<String>();
    let _ = std::thread::Builder::new()
        .name("kb-session-stdin".into())
        .spawn(move || {
            for line in std::io::stdin().lock().lines() {
                let Ok(line) = line else { break };
                if tx.send(line).is_err() {
                    break;
                }
            }
        });
    while let Ok(line) = rx.recv_timeout(HELPER_IDLE_EXIT) {
        match line.trim() {
            "idle" => say(match idle.as_ref().map(idle_ms) {
                Some(Ok(ms)) => format!("idle {ms}"),
                Some(Err(e)) => format!("err idle {e}"),
                None => "err idle no IdleMonitor proxy".to_string(),
            }),
            "geom" => say(match geometry(&conn) {
                Ok(g) => format!("geom {}", serde_json::to_string(&g).unwrap_or_default()),
                Err(e) => format!("err geom {e}"),
            }),
            _ => {}
        }
    }
}

fn idle_ms(p: &zbus::blocking::Proxy<'_>) -> Result<u64, zbus::Error> {
    p.call_method("GetIdletime", &())?
        .body()
        .deserialize::<u64>()
}

/// `GetCurrentState`'s reply: serial, monitors, logical monitors,
/// properties — the shape measured on GNOME 46 by `capture::portal::mutter`
/// (`(ua((ssss)a(siiddada{sv})a{sv})a(iiduba(ssss)a{sv})a{sv})`). ⚠️ The
/// whole body must be deserialised: zvariant matches the full signature.
type CurrentState = (
    u32,
    Vec<MonitorEntry>,
    Vec<LogicalMonitorEntry>,
    HashMap<String, OwnedValue>,
);

#[derive(serde::Deserialize, zbus::zvariant::Type)]
struct MonitorSpec {
    connector: String,
    #[allow(dead_code)]
    vendor: String,
    #[allow(dead_code)]
    product: String,
    #[allow(dead_code)]
    serial: String,
}

#[derive(serde::Deserialize, zbus::zvariant::Type)]
struct MonitorMode {
    #[allow(dead_code)]
    id: String,
    width: i32,
    height: i32,
    #[allow(dead_code)]
    refresh: f64,
    #[allow(dead_code)]
    preferred_scale: f64,
    #[allow(dead_code)]
    supported_scales: Vec<f64>,
    properties: HashMap<String, OwnedValue>,
}

#[derive(serde::Deserialize, zbus::zvariant::Type)]
struct MonitorEntry {
    spec: MonitorSpec,
    modes: Vec<MonitorMode>,
    #[allow(dead_code)]
    properties: HashMap<String, OwnedValue>,
}

#[derive(serde::Deserialize, zbus::zvariant::Type)]
struct LogicalMonitorEntry {
    x: i32,
    y: i32,
    scale: f64,
    transform: u32,
    primary: bool,
    monitors: Vec<MonitorSpec>,
    #[allow(dead_code)]
    properties: HashMap<String, OwnedValue>,
}

fn geometry(conn: &zbus::blocking::Connection) -> Result<Geometry, zbus::Error> {
    let p = zbus::blocking::Proxy::new(conn, DISPLAY_BUS, DISPLAY_PATH, DISPLAY_IFACE)?;
    let msg = p.call_method("GetCurrentState", &())?;
    let (_serial, monitors, logical, props): CurrentState = msg.body().deserialize()?;
    let current: Vec<ModeIn> = monitors
        .iter()
        .filter_map(|m| {
            let mode = m.modes.iter().find(|md| {
                md.properties
                    .get("is-current")
                    .is_some_and(|v| matches!(<&Value>::from(v), Value::Bool(true)))
            })?;
            Some(ModeIn {
                connector: m.spec.connector.clone(),
                width: mode.width,
                height: mode.height,
            })
        })
        .collect();
    let logical: Vec<LogicalIn> = logical
        .iter()
        .map(|l| LogicalIn {
            x: l.x,
            y: l.y,
            scale: l.scale,
            transform: l.transform,
            primary: l.primary,
            connectors: l.monitors.iter().map(|s| s.connector.clone()).collect(),
        })
        .collect();
    let layout_mode = props
        .get("layout-mode")
        .and_then(|v| match <&Value>::from(v) {
            Value::U32(n) => Some(*n),
            _ => None,
        })
        .unwrap_or(gnome::LAYOUT_LOGICAL);
    Ok(gnome::layout(&logical, &current, layout_mode))
}

// ── The daemon's side ──────────────────────────────────────────────────────

/// Why the helper cannot answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LinkError {
    /// Nobody is at the screen to run it as.
    NoSession,
    /// It could not be started.
    Spawn(String),
    /// It did not answer in time — the link is no longer trustworthy (a late
    /// answer would be read as the next one's), so the caller drops it.
    Timeout,
    /// It exited.
    Gone,
    /// It answered, with an error.
    Refused(String),
}

impl std::fmt::Display for LinkError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LinkError::NoSession => f.write_str("no graphical session"),
            LinkError::Spawn(e) => write!(f, "could not start the session helper: {e}"),
            LinkError::Timeout => f.write_str("the session helper did not answer in time"),
            LinkError::Gone => f.write_str("the session helper exited"),
            LinkError::Refused(e) => write!(f, "the session helper refused: {e}"),
        }
    }
}

/// A running helper inside the person's session. Dropping it kills the
/// child; its stdin closing would end it anyway.
pub struct Link {
    child: Child,
    stdin: ChildStdin,
    lines: Receiver<String>,
    /// What the session answers (the helper's hello).
    pub idle_ok: bool,
    pub geom_ok: bool,
}

impl Link {
    /// Start the helper as whoever holds the active graphical session and
    /// wait for its hello.
    pub fn open(hello_timeout: Duration) -> Result<Link, LinkError> {
        use crate::capture::portal::helper::{SpawnError, spawn_child};
        let mut child = match spawn_child(&["--keep-busy"], true) {
            Ok(c) => c,
            Err(SpawnError::NoSession) => return Err(LinkError::NoSession),
            Err(SpawnError::Other(e)) => return Err(LinkError::Spawn(e)),
        };
        let (Some(stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
            let _ = child.kill();
            let _ = child.wait();
            return Err(LinkError::Spawn("no pipes to the helper".into()));
        };
        let (tx, lines) = std::sync::mpsc::channel();
        let reader = std::thread::Builder::new()
            .name("kb-session-read".into())
            .spawn(move || {
                for line in BufReader::new(stdout).lines() {
                    let Ok(line) = line else { break };
                    // Only marked lines: anything else is a library's chatter.
                    if line.starts_with(MARK) && tx.send(line).is_err() {
                        break;
                    }
                }
            });
        let mut link = Link {
            child,
            stdin,
            lines,
            idle_ok: false,
            geom_ok: false,
        };
        if let Err(e) = reader {
            return Err(LinkError::Spawn(format!("reader thread: {e}")));
        }
        match link.next(hello_timeout)? {
            Reply::Hello { idle, geom } => {
                link.idle_ok = idle;
                link.geom_ok = geom;
                Ok(link)
            }
            Reply::Err(e) => Err(LinkError::Refused(e)),
            _ => Err(LinkError::Refused("no hello".into())),
        }
    }

    fn next(&mut self, timeout: Duration) -> Result<Reply, LinkError> {
        let deadline = Instant::now() + timeout;
        loop {
            let left = deadline.saturating_duration_since(Instant::now());
            match self.lines.recv_timeout(left) {
                // A verb this build does not know is skipped, never an error.
                Ok(line) => {
                    if let Some(r) = gnome::parse_reply(&line) {
                        return Ok(r);
                    }
                }
                Err(RecvTimeoutError::Timeout) => return Err(LinkError::Timeout),
                Err(RecvTimeoutError::Disconnected) => return Err(LinkError::Gone),
            }
        }
    }

    fn ask(&mut self, q: &str, timeout: Duration) -> Result<Reply, LinkError> {
        writeln!(self.stdin, "{q}")
            .and_then(|()| self.stdin.flush())
            .map_err(|_| LinkError::Gone)?;
        self.next(timeout)
    }

    /// Is the helper still running? It exits by itself when asked nothing
    /// for [`HELPER_IDLE_EXIT`], and with the session it runs in.
    pub fn alive(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }

    /// Milliseconds since the session's last input.
    pub fn idle_ms(&mut self, timeout: Duration) -> Result<u64, LinkError> {
        match self.ask("idle", timeout)? {
            Reply::Idle(ms) => Ok(ms),
            Reply::Err(e) => Err(LinkError::Refused(e)),
            _ => Err(LinkError::Refused("an answer to another question".into())),
        }
    }

    /// The monitors, as an absolute device sees them.
    pub fn geometry(&mut self, timeout: Duration) -> Result<Geometry, LinkError> {
        match self.ask("geom", timeout)? {
            Reply::Geom(g) => Ok(g),
            Reply::Err(e) => Err(LinkError::Refused(e)),
            _ => Err(LinkError::Refused("an answer to another question".into())),
        }
    }
}

impl Drop for Link {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}
