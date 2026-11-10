// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-84 D6 / #1035 — WHO holds the local port a declared route cannot bind.
//!
//! #1035's wedge read "local port 1081 is not available" for two days, which
//! is indistinguishable from a corporate proxy squatting the port. The field
//! answer, found by hand in the TCP table, was a PID that no longer existed
//! whose listeners were still bound — held by the companion, which had
//! inherited the sockets from that dead daemon. This names the holder in the
//! log once a route has been refused its port for [`STUCK_AFTER`], and again
//! every [`EVERY`] while it stays stuck: this daemon itself, the companion, a
//! foreign process, or a process that is gone.
//!
//! Diagnostics only: nothing here kills, frees or changes anything.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// How long a route must be refused its port before the holder is named.
pub const STUCK_AFTER: Duration = Duration::from_secs(120);
/// Between repeats while it stays stuck.
pub const EVERY: Duration = Duration::from_secs(600);

/// Does a create error say the local port is taken? The phrase is our own
/// (`client_mgr::probe_local_port`), never a localized OS message.
pub fn is_port_busy(message: &str) -> bool {
    message.contains("is not available")
}

struct Streak {
    since: Instant,
    logged: Option<Instant>,
}

/// Per-route "refused its port" streaks. Pure: the caller passes `now`.
#[derive(Default)]
pub struct Ledger {
    streaks: HashMap<String, Streak>,
}

impl Ledger {
    /// A create for `route` failed; `port_busy` = because its port is taken.
    /// `true` = look the holder up and log it now.
    pub fn failed(&mut self, route: &str, port_busy: bool, now: Instant) -> bool {
        if !port_busy {
            self.streaks.remove(route);
            return false;
        }
        let s = self.streaks.entry(route.to_string()).or_insert(Streak {
            since: now,
            logged: None,
        });
        if now.duration_since(s.since) < STUCK_AFTER {
            return false;
        }
        match s.logged {
            Some(at) if now.duration_since(at) < EVERY => false,
            _ => {
                s.logged = Some(now);
                true
            }
        }
    }

    /// The route got its flow: the streak is over.
    pub fn ok(&mut self, route: &str) {
        self.streaks.remove(route);
    }
}

static LEDGER: Mutex<Option<Ledger>> = Mutex::new(None);

/// [`Ledger::failed`] on the process-wide ledger.
pub fn note_failure(route: &str, message: &str) -> bool {
    LEDGER
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .get_or_insert_with(Ledger::default)
        .failed(route, is_port_busy(message), Instant::now())
}

/// [`Ledger::ok`] on the process-wide ledger.
pub fn note_ok(route: &str) {
    if let Some(l) = LEDGER.lock().unwrap_or_else(|p| p.into_inner()).as_mut() {
        l.ok(route);
    }
}

/// Who holds a listening port.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Holder {
    /// This very process — a listener no flow owns.
    ThisDaemon { pid: u32 },
    /// A live process (`image` when it could be read).
    Alive { pid: u32, image: Option<String> },
    /// The table names a PID that no longer exists: another process holds a
    /// duplicate of its socket (on Windows, a child that inherited it).
    Gone { pid: u32 },
    /// No listener found for the port, or no way to ask.
    Unknown,
}

/// The one log line's worth of `h`, with the next step where there is one.
pub fn describe(h: &Holder) -> String {
    match h {
        Holder::ThisDaemon { pid } => format!(
            "held by this daemon itself (pid {pid}) — a listener no flow owns; restarting the \
             service frees it (#1035)"
        ),
        Holder::Alive { pid, image } => {
            let name = image.as_deref().unwrap_or("(image not readable)");
            let is_companion = image.as_deref().is_some_and(|i| {
                let i = i.to_ascii_lowercase();
                i.ends_with("meshharbor-desktop.exe") || i.ends_with("meshharbor-desktop")
            });
            if is_companion {
                format!(
                    "held by the companion {name} (pid {pid}) — it inherited a listener from a \
                     daemon that has since exited; quitting the companion frees it (#1035)"
                )
            } else {
                format!("held by {name} (pid {pid})")
            }
        }
        Holder::Gone { pid } => format!(
            "held by pid {pid}, which no longer exists — another process holds a duplicate of \
             its socket (a child that inherited it; #1035)"
        ),
        Holder::Unknown => "holder unknown (no listener found for the port)".to_string(),
    }
}

/// Look the holder of `port` up. Blocking (a table read, a process open, on
/// Linux a `/proc` walk, on macOS an `lsof` run of at most 5 s): call it off
/// the async runtime.
pub fn lookup(port: u16) -> Holder {
    let pid = listener_pid(port);
    let Some(pid) = pid else {
        return Holder::Unknown;
    };
    if pid == std::process::id() {
        return Holder::ThisDaemon { pid };
    }
    process_state(pid)
}

// ─── Windows: the TCP table names the owning PID ───────────────────────────

#[cfg(target_os = "windows")]
fn listener_pid(port: u16) -> Option<u32> {
    use windows_sys::Win32::NetworkManagement::IpHelper::{
        GetExtendedTcpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCPROW_OWNER_PID,
        TCP_TABLE_OWNER_PID_LISTENER,
    };
    const AF_INET: u32 = 2;
    const AF_INET6: u32 = 23;
    const ERROR_INSUFFICIENT_BUFFER: u32 = 122;

    // One table read into u32-aligned storage (every row field is a u32 or a
    // byte array, so 4 is the rows' alignment).
    fn table(af: u32) -> Option<Vec<u32>> {
        let mut size = 0u32;
        // SAFETY: a size query — null buffer, valid out-param.
        let rc = unsafe {
            GetExtendedTcpTable(
                std::ptr::null_mut(),
                &mut size,
                0,
                af,
                TCP_TABLE_OWNER_PID_LISTENER,
                0,
            )
        };
        if rc != ERROR_INSUFFICIENT_BUFFER || size == 0 {
            return None;
        }
        let mut buf = vec![0u32; (size as usize).div_ceil(4) + 1];
        let mut len = (buf.len() * 4) as u32;
        // SAFETY: `buf` holds `len` bytes, suitably aligned.
        let rc = unsafe {
            GetExtendedTcpTable(
                buf.as_mut_ptr().cast(),
                &mut len,
                0,
                af,
                TCP_TABLE_OWNER_PID_LISTENER,
                0,
            )
        };
        (rc == 0).then_some(buf)
    }

    // `dwLocalPort` carries the port in network byte order in its low word.
    let port_of = |raw: u32| u16::from_be((raw & 0xffff) as u16);

    if let Some(buf) = table(AF_INET) {
        let n = buf[0] as usize;
        // SAFETY: the table is `dwNumEntries` followed by that many rows; the
        // API sized it, and `n` came from it.
        let rows = unsafe {
            std::slice::from_raw_parts(buf.as_ptr().add(1).cast::<MIB_TCPROW_OWNER_PID>(), n)
        };
        if let Some(r) = rows.iter().find(|r| port_of(r.dwLocalPort) == port) {
            return Some(r.dwOwningPid);
        }
    }
    if let Some(buf) = table(AF_INET6) {
        let n = buf[0] as usize;
        // SAFETY: as above, for the IPv6 row layout.
        let rows = unsafe {
            std::slice::from_raw_parts(buf.as_ptr().add(1).cast::<MIB_TCP6ROW_OWNER_PID>(), n)
        };
        if let Some(r) = rows.iter().find(|r| port_of(r.dwLocalPort) == port) {
            return Some(r.dwOwningPid);
        }
    }
    None
}

#[cfg(target_os = "windows")]
fn process_state(pid: u32) -> Holder {
    use windows_sys::Win32::Foundation::{CloseHandle, ERROR_INVALID_PARAMETER, GetLastError};
    use windows_sys::Win32::System::Threading::{
        OpenProcess, PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION,
        QueryFullProcessImageNameW,
    };
    // SAFETY: plain open by pid; the handle is closed below.
    let h = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if h.is_null() {
        // SAFETY: thread-local read.
        let err = unsafe { GetLastError() };
        // A PID that does not exist is exactly #1035's shape.
        return if err == ERROR_INVALID_PARAMETER {
            Holder::Gone { pid }
        } else {
            Holder::Alive { pid, image: None }
        };
    }
    let mut buf = [0u16; 1024];
    let mut len = buf.len() as u32;
    // SAFETY: `buf` holds `len` wide chars; `h` is a live process handle.
    let ok =
        unsafe { QueryFullProcessImageNameW(h, PROCESS_NAME_WIN32, buf.as_mut_ptr(), &mut len) };
    // SAFETY: we own `h`.
    unsafe { CloseHandle(h) };
    let image = (ok != 0).then(|| String::from_utf16_lossy(&buf[..len as usize]));
    Holder::Alive { pid, image }
}

// ─── Linux: /proc/net/tcp names the socket inode, /proc/*/fd its owner ─────

/// Socket inodes LISTENING on `port` in a `/proc/net/tcp`/`tcp6` table.
#[cfg(any(target_os = "linux", test))]
fn listen_inodes(table: &str, port: u16) -> Vec<u64> {
    table
        .lines()
        .skip(1)
        .filter_map(|line| {
            let f: Vec<&str> = line.split_whitespace().collect();
            let local = f.get(1)?;
            let state = f.get(3)?;
            let inode = f.get(9)?.parse::<u64>().ok()?;
            let p = u16::from_str_radix(local.rsplit(':').next()?, 16).ok()?;
            (*state == "0A" && p == port && inode != 0).then_some(inode)
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn listener_pid(port: u16) -> Option<u32> {
    let mut inodes = Vec::new();
    for t in ["/proc/net/tcp", "/proc/net/tcp6"] {
        if let Ok(text) = std::fs::read_to_string(t) {
            inodes.extend(listen_inodes(&text, port));
        }
    }
    if inodes.is_empty() {
        return None;
    }
    let wanted: Vec<String> = inodes.iter().map(|i| format!("socket:[{i}]")).collect();
    for entry in std::fs::read_dir("/proc").ok()?.flatten() {
        let Some(pid) = entry
            .file_name()
            .to_str()
            .and_then(|s| s.parse::<u32>().ok())
        else {
            continue;
        };
        let Ok(fds) = std::fs::read_dir(entry.path().join("fd")) else {
            continue;
        };
        for fd in fds.flatten() {
            if let Ok(target) = std::fs::read_link(fd.path())
                && wanted.iter().any(|w| target.as_os_str() == w.as_str())
            {
                return Some(pid);
            }
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn process_state(pid: u32) -> Holder {
    match std::fs::read_link(format!("/proc/{pid}/exe")) {
        Ok(p) => Holder::Alive {
            pid,
            image: Some(p.display().to_string()),
        },
        Err(_) => Holder::Alive { pid, image: None },
    }
}

// ─── macOS: `lsof` names the listening process ─────────────────────────────

/// The listener's PID from `lsof`, which every macOS ships at this path.
/// The native route, libproc's socket-info flavour, needs `socket_fdinfo`
/// and its unions, which `libc` does not declare, and a hand-copied xnu
/// layout that is off by a field reads as a confident wrong PID. The root
/// daemon sees every process; a per-user one sees only its own user's, so a
/// foreign holder is `Unknown` there, as before. `lsof` lists the processes
/// that hold the socket now, so an inheritor is named itself (never
/// [`Holder::Gone`]). Bounded at 5 s: a lookup must never hold its thread.
#[cfg(target_os = "macos")]
fn listener_pid(port: u16) -> Option<u32> {
    use std::io::Read;
    use std::time::{Duration, Instant};
    let mut child = std::process::Command::new("/usr/sbin/lsof")
        // -n -P: no DNS, no port names; -b: never block in the kernel;
        // -w: no warnings; -t: PIDs only, one per line.
        .args(["-nP", "-b", "-w", "-t", "-sTCP:LISTEN"])
        .arg(format!("-iTCP:{port}"))
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .spawn()
        .ok()?;
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => break,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(Duration::from_millis(50)),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return None;
            }
        }
    }
    let mut out = String::new();
    child.stdout.take()?.read_to_string(&mut out).ok()?;
    first_pid(&out)
}

/// The first PID in `lsof -t` output, which is one PID per line.
#[cfg(any(target_os = "macos", test))]
fn first_pid(lsof_terse: &str) -> Option<u32> {
    lsof_terse.lines().find_map(|l| l.trim().parse().ok())
}

#[cfg(target_os = "macos")]
fn process_state(pid: u32) -> Holder {
    let mut buf = vec![0u8; libc::PROC_PIDPATHINFO_MAXSIZE as usize];
    // SAFETY: `buf` holds the size passed, and the call writes at most that.
    let n = unsafe {
        libc::proc_pidpath(
            pid as libc::c_int,
            buf.as_mut_ptr().cast(),
            buf.len() as u32,
        )
    };
    let image = (n > 0).then(|| String::from_utf8_lossy(&buf[..n as usize]).into_owned());
    Holder::Alive { pid, image }
}

// ─── elsewhere: no cheap, reliable answer ──────────────────────────────────

#[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
fn listener_pid(_port: u16) -> Option<u32> {
    None
}

#[cfg(not(any(target_os = "windows", target_os = "linux", target_os = "macos")))]
fn process_state(pid: u32) -> Holder {
    Holder::Alive { pid, image: None }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn busy_is_our_own_phrase() {
        assert!(is_port_busy(
            "local port 1081 is not available: Only one usage of each socket address \
             (protocol/network address/port) is normally permitted. (os error 10048)"
        ));
        assert!(!is_port_busy("peer offline"));
    }

    /// Named after [`STUCK_AFTER`], then every [`EVERY`]; a different error
    /// or a success ends the streak.
    #[test]
    fn ledger_names_the_holder_after_two_minutes_then_every_ten() {
        let mut l = Ledger::default();
        let t0 = Instant::now();
        assert!(!l.failed("r1", true, t0), "first refusal: too early");
        assert!(!l.failed("r1", true, t0 + Duration::from_secs(60)));
        assert!(
            l.failed("r1", true, t0 + STUCK_AFTER),
            "stuck for two minutes"
        );
        assert!(!l.failed("r1", true, t0 + STUCK_AFTER + Duration::from_secs(30)));
        assert!(
            l.failed("r1", true, t0 + STUCK_AFTER + EVERY),
            "repeated while it stays stuck"
        );
        // A different failure ends the streak; the clock starts over.
        assert!(!l.failed(
            "r1",
            false,
            t0 + STUCK_AFTER + EVERY + Duration::from_secs(1)
        ));
        let t1 = t0 + STUCK_AFTER + EVERY + Duration::from_secs(2);
        assert!(!l.failed("r1", true, t1));
        assert!(l.failed("r1", true, t1 + STUCK_AFTER));
        // So does a success.
        l.ok("r1");
        assert!(!l.failed("r1", true, t1 + STUCK_AFTER + Duration::from_secs(1)));
        // Routes are independent.
        assert!(!l.failed("r2", true, t1));
    }

    /// REAL `/proc/net/tcp` rows, captured in WSL 2026-09-25 with a Python
    /// listener on 127.0.0.1:41999 (0xA40F) and one connection to it: the
    /// listener, the client side, and the ACCEPTED side — which shares the
    /// local port in state 01 and must not count.
    #[test]
    fn proc_net_tcp_finds_only_listeners_on_the_port() {
        let table = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
            \x20  2: 0100007F:A40F 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 15473497 1 0000000000000000 100 0 0 10 0\n\
            \x20 11: 0100007F:A927 0100007F:A40F 01 00000000:00000000 00:00000000 00000000  1000        0 15473498 2 0000000000000000 20 0 0 10 -1\n\
            \x20 12: 0100007F:A40F 0100007F:A927 01 00000000:00000000 00:00000000 00000000  1000        0 15473499 1 0000000000000000 20 0 0 10 -1\n";
        assert_eq!(listen_inodes(table, 41999), vec![15473497]);
        assert!(
            listen_inodes(table, 0xA927).is_empty(),
            "a client's local port is not a listener"
        );
        assert!(listen_inodes(table, 8080).is_empty());
    }

    #[test]
    fn descriptions_name_the_next_step() {
        assert!(describe(&Holder::ThisDaemon { pid: 7 }).contains("restarting the service"));
        let companion = describe(&Holder::Alive {
            pid: 9,
            image: Some(r"C:\Program Files\MeshHarbor\meshharbor-desktop.exe".into()),
        });
        assert!(companion.contains("quitting the companion"), "{companion}");
        let mac_companion = describe(&Holder::Alive {
            pid: 10,
            image: Some("/Applications/MeshHarbor.app/Contents/MacOS/meshharbor-desktop".into()),
        });
        assert!(
            mac_companion.contains("quitting the companion"),
            "{mac_companion}"
        );
        let foreign = describe(&Holder::Alive {
            pid: 11,
            image: Some(r"C:\Program Files\Proxy\proxy.exe".into()),
        });
        assert!(foreign.starts_with(r"held by C:\Program Files\Proxy\proxy.exe (pid 11)"));
        assert!(describe(&Holder::Gone { pid: 52404 }).contains("no longer exists"));
    }

    /// `lsof -t` (macOS): one PID per line, and the first names the holder.
    #[test]
    fn lsof_terse_output_names_the_first_pid() {
        assert_eq!(first_pid("4321\n4400\n"), Some(4321));
        assert_eq!(first_pid(" 512 \n"), Some(512));
        assert_eq!(first_pid(""), None, "no listener: lsof prints nothing");
        assert_eq!(first_pid("lsof: WARNING\n77\n"), Some(77));
    }

    /// The lookup against a REAL listener this test binds: it must name this
    /// very process — the one-process shape of #1035's first report. (CI
    /// runs it on Windows and Linux; no lane runs meshharbord's tests on macOS.)
    #[cfg(any(target_os = "windows", target_os = "linux", target_os = "macos"))]
    #[test]
    fn lookup_names_this_process_for_its_own_listener() {
        let held = std::net::TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = held.local_addr().unwrap().port();
        assert_eq!(
            lookup(port),
            Holder::ThisDaemon {
                pid: std::process::id()
            }
        );
    }
}
