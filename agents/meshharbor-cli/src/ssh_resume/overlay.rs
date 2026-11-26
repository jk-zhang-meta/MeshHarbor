// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-141 — Human-friendly, zero-corruption top-row SSH recovery status banner
//! and OSC 2 window title (Mosh model).
//!
//! While the transport is disconnected or the target daemon is updating, the
//! banner paints cleanly onto row 1 of the terminal WITHOUT injecting raw lines
//! into the remote shell or corrupting full-screen TUIs (`vim`, `tmux`, `htop`,
//! `nvitop`). The instant reattach succeeds, row 1 is repainted verbatim from
//! the client-side shadow `VtScreenTracker`.

use unicode_width::UnicodeWidthChar;

/// Current recovery reason rendered in the top-row banner.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OverlayReason {
    TargetUpdating { to_version: Option<String> },
    TargetRestarting,
    LinkSuspect,
    NetworkReconnecting,
}

/// Detect whether the terminal locale prefers Chinese (`zh_*`).
pub fn prefers_zh() -> bool {
    for key in ["LC_ALL", "LC_MESSAGES", "LANG"] {
        if let Ok(val) = std::env::var(key) {
            let lower = val.trim().to_ascii_lowercase();
            if lower.starts_with("zh") {
                return true;
            }
            if !lower.is_empty() && lower != "c" && lower != "posix" {
                return false;
            }
        }
    }
    false
}

/// Build the single-line human-readable text for the top-row banner (fits
/// strictly within `cols` display columns so it NEVER wraps onto row 2).
pub fn format_banner_text(
    device: &str,
    reason: &OverlayReason,
    disconnected_secs: u64,
    queued_bytes: usize,
    ctrl_c_armed: bool,
    cols: u16,
    zh: bool,
) -> String {
    let raw = if ctrl_c_armed {
        if zh {
            format!(
                " ! SSH 会话恢复中 ({device}, {disconnected_secs}s) · 再按一次 Ctrl-C 退出本地并保持远端运行 · ~d 后台挂起"
            )
        } else {
            format!(
                " ! SSH reconnecting ({device}, {disconnected_secs}s) · press Ctrl-C again to detach locally (remote keeps running) · ~d detach"
            )
        }
    } else if zh {
        let why = match reason {
            OverlayReason::TargetUpdating { to_version: Some(v) } => {
                format!("目标正在更新至 {v}")
            }
            OverlayReason::TargetUpdating { to_version: None } => "目标正在更新".to_string(),
            OverlayReason::TargetRestarting => "目标服务重启中".to_string(),
            OverlayReason::LinkSuspect => "链路检测中".to_string(),
            OverlayReason::NetworkReconnecting => "网络重连中".to_string(),
        };
        let queue_hint = if queued_bytes > 0 {
            format!(" · 已缓存 {queued_bytes}B 输入")
        } else {
            " · 输入已自动缓存".to_string()
        };
        format!(
            " ⏳ MeshHarbor SSH 会话恢复中 — {device} ({why}) · {disconnected_secs}s{queue_hint} · ~d 挂起 · ~. 结束"
        )
    } else {
        let why = match reason {
            OverlayReason::TargetUpdating { to_version: Some(v) } => {
                format!("target updating to {v}")
            }
            OverlayReason::TargetUpdating { to_version: None } => "target updating".to_string(),
            OverlayReason::TargetRestarting => "target restarting".to_string(),
            OverlayReason::LinkSuspect => "probing link".to_string(),
            OverlayReason::NetworkReconnecting => "reconnecting".to_string(),
        };
        let queue_hint = if queued_bytes > 0 {
            format!(" · {queued_bytes}B input queued")
        } else {
            " · input queued".to_string()
        };
        format!(
            " ⏳ MeshHarbor SSH reconnecting — {device} ({why}) · {disconnected_secs}s{queue_hint} · ~d detach · ~. end"
        )
    };

    fit_to_width(&raw, usize::from(cols.max(20)))
}

/// Produce the complete ANSI escape sequence to draw the top-row overlay bar
/// and update OSC 2 window title without moving or clobbering the underlying
/// shadow cursor state.
pub fn render_banner_ansi(
    device: &str,
    reason: &OverlayReason,
    disconnected_secs: u64,
    queued_bytes: usize,
    ctrl_c_armed: bool,
    cols: u16,
    zh: bool,
) -> Vec<u8> {
    let text = format_banner_text(
        device,
        reason,
        disconnected_secs,
        queued_bytes,
        ctrl_c_armed,
        cols,
        zh,
    );
    let title = if zh {
        format!("⏳ SSH 会话恢复中 ({disconnected_secs}s) — {device}")
    } else {
        format!("⏳ SSH reconnecting ({disconnected_secs}s) — {device}")
    };
    // Amber bar with dark bold ink when reconnecting; crimson highlight if
    // double-Ctrl-C confirm is armed.
    let style = if ctrl_c_armed {
        "\x1b[0;1;97;41m"
    } else {
        "\x1b[0;1;30;43m"
    };
    let mut out = Vec::with_capacity(text.len() + title.len() + 64);
    // Save/restore cursor via DEC ESC 7 / ESC 8 so painting the top-row overlay
    // never leaves the cursor stranded on row 1 if live output resumes.
    out.extend_from_slice(b"\x1b7\x1b[?25l\x1b[1;1H");
    out.extend_from_slice(style.as_bytes());
    out.extend_from_slice(text.as_bytes());
    out.extend_from_slice(b"\x1b[0m\x1b8");
    out.extend_from_slice(format!("\x1b]2;{title}\x07").as_bytes());
    out
}

/// Restore the terminal window title after reattach.
pub fn restore_title_ansi(device: &str) -> Vec<u8> {
    format!("\x1b]2;mh ssh {device}\x07").into_bytes()
}

/// Truncate or space-pad `s` to exact display width `max_cols` (CJK-aware).
fn fit_to_width(s: &str, max_cols: usize) -> String {
    let mut out = String::with_capacity(s.len());
    let mut width = 0usize;
    for ch in s.chars() {
        let w = UnicodeWidthChar::width(ch).unwrap_or(0);
        if width + w > max_cols {
            break;
        }
        out.push(ch);
        width += w;
    }
    while width < max_cols {
        out.push(' ');
        width += 1;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use unicode_width::UnicodeWidthStr;

    #[test]
    fn fr141_banner_fits_exact_display_width_for_zh_and_en() {
        let zh_bar = format_banner_text(
            "dev-box",
            &OverlayReason::TargetUpdating {
                to_version: Some("0.4.219".into()),
            },
            7,
            12,
            false,
            80,
            true,
        );
        assert_eq!(UnicodeWidthStr::width(zh_bar.as_str()), 80);
        assert!(zh_bar.contains("会话恢复中"));

        let en_bar = format_banner_text(
            "dev-box",
            &OverlayReason::NetworkReconnecting,
            15,
            0,
            true,
            60,
            false,
        );
        assert_eq!(UnicodeWidthStr::width(en_bar.as_str()), 60);
        assert!(en_bar.contains("Ctrl-C again"));
    }
}
