// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-141 — Resumable interactive SSH client selection and lifecycle commands.

pub mod client;
pub mod escape;
pub mod overlay;
pub mod store;

use std::io::IsTerminal;

use anyhow::Result;

/// Whether `mh ssh <device> [args...]` should use the built-in resumable
/// `russh`+`crossterm` client or delegate byte-for-byte to system OpenSSH.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteDecision {
    /// Built-in resumable interactive PTY (`mh ssh <dev>` or `mh ssh <dev> -t <cmd>`).
    BuiltinPty { command: Option<String> },
    /// Delegate to system OpenSSH unchanged (`-L/-R/-D/-W/-J/-N/-A/-X/-o`,
    /// `--no-resume`, non-TTY piped exec, etc.).
    OpenSsh,
}

/// Decide whether built-in resumable mode applies for `args`.
pub fn decide_route(args: &[String], no_resume: bool, stdin_is_tty: bool) -> RouteDecision {
    if no_resume || env_disabled() || !stdin_is_tty {
        return RouteDecision::OpenSsh;
    }
    if args.is_empty() {
        return RouteDecision::BuiltinPty { command: None };
    }
    // Support `mh ssh <dev> -t <cmd...>` for interactive command PTYs.
    if args[0] == "-t" && args.len() >= 2 && !args[1].starts_with('-') {
        let cmd = args[1..].join(" ");
        return RouteDecision::BuiltinPty { command: Some(cmd) };
    }
    // Any other OpenSSH flag (`-L -R -D -W -J -N -A -X -o ...`) or plain
    // non-interactive remote command keeps system OpenSSH unchanged.
    RouteDecision::OpenSsh
}

pub fn stdin_is_tty() -> bool {
    std::io::stdin().is_terminal() && std::io::stdout().is_terminal()
}

fn env_disabled() -> bool {
    if let Ok(v) = std::env::var("MESHHARBOR_SSH_RESUME") {
        let t = v.trim();
        return t == "0" || t.eq_ignore_ascii_case("false") || t.eq_ignore_ascii_case("off");
    }
    false
}

/// Print saved local resumable SSH sessions for `device`.
pub fn print_sessions(device: &str) -> Result<i32> {
    let sessions = store::list_for_device(device);
    let zh = overlay::prefers_zh();
    if sessions.is_empty() {
        if zh {
            println!("设备 {device} 当前没有可恢复的本地 SSH 会话记录。");
        } else {
            println!("No saved resumable SSH sessions for {device}.");
        }
        return Ok(0);
    }
    let now = meshharbor_node_core::pty_resume::now_unix_ms();
    if zh {
        println!("设备 {device} 的可恢复 SSH 会话（使用 `mh ssh {device} --resume <ID>` 重新接回）：");
    } else {
        println!("Saved resumable SSH sessions for {device} (use `mh ssh {device} --resume <ID>`):");
    }
    for s in sessions {
        let rem_min = s.deadline_ms.saturating_sub(now) / 60_000;
        println!(
            "  {}  addr={}:{}  rx={}B  expires_in={}m",
            s.sid.short_hex(),
            s.address,
            s.port,
            s.last_rx,
            rem_min
        );
    }
    Ok(0)
}

/// Emit a non-intrusive dim hint if detached sessions already exist for `device`.
pub fn hint_detached_sessions(device: &str) {
    let sessions = store::list_for_device(device);
    if sessions.is_empty() {
        return;
    }
    let zh = overlay::prefers_zh();
    let newest = &sessions[0];
    if zh {
        eprintln!(
            "\x1b[2m提示: 检测到 {} 个已挂起的 {} SSH 会话（最新 {}）。可随时运行 `mh ssh {} --resume` 接回。\x1b[0m",
            sessions.len(),
            device,
            newest.sid.short_hex(),
            device
        );
    } else {
        eprintln!(
            "\x1b[2mHint: {} detached SSH session(s) on {} (latest {}). Run `mh ssh {} --resume` to reattach.\x1b[0m",
            sessions.len(),
            device,
            newest.sid.short_hex(),
            device
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fr141_route_selection_preserves_openssh_forwarding() {
        assert_eq!(
            decide_route(&[], false, true),
            RouteDecision::BuiltinPty { command: None }
        );
        assert_eq!(
            decide_route(&["-t".into(), "htop".into()], false, true),
            RouteDecision::BuiltinPty {
                command: Some("htop".into())
            }
        );
        assert_eq!(decide_route(&[], true, true), RouteDecision::OpenSsh);
        assert_eq!(decide_route(&[], false, false), RouteDecision::OpenSsh);
        assert_eq!(
            decide_route(&["-L".into(), "8080:127.0.0.1:80".into()], false, true),
            RouteDecision::OpenSsh
        );
        assert_eq!(
            decide_route(&["uptime".into()], false, true),
            RouteDecision::OpenSsh
        );
    }
}
