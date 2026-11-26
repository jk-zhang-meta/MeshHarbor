// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-141 — OpenSSH-style escape sequences (`~d`, `~.`, `~~`, `~?`) and
//! human-friendly double-`Ctrl-C` local detach while disconnected.

use std::time::{Duration, Instant};

/// Action yielded by [`InputFilter::feed`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilterAction {
    /// Forward these raw bytes into the remote session (or c2s queue).
    Forward(Vec<u8>),
    /// `~d` — detach locally and print resume command; remote stays alive.
    Detach,
    /// `~.` — terminate remote session (if connected) or exit locally with `--kill` hint.
    Terminate,
    /// `~?` — print short escape reference without sending to remote.
    Help,
    /// 1st `Ctrl-C` while disconnected: byte was forwarded to queue, arm warning banner.
    CtrlCFirstQueued,
    /// 2nd `Ctrl-C` within 1.5 s while disconnected: discard queued `^C` and detach locally!
    CtrlCDoubleDetach,
}

const DOUBLE_CTRL_C_WINDOW: Duration = Duration::from_millis(1500);

/// Stateful byte filter for local TTY stdin.
#[derive(Debug)]
pub struct InputFilter {
    at_line_start: bool,
    pending_tilde: bool,
    first_ctrl_c_at: Option<Instant>,
}

impl Default for InputFilter {
    fn default() -> Self {
        Self::new()
    }
}

impl InputFilter {
    pub fn new() -> Self {
        Self {
            at_line_start: true,
            pending_tilde: false,
            first_ctrl_c_at: None,
        }
    }

    pub fn is_ctrl_c_armed(&self, now: Instant) -> bool {
        self.first_ctrl_c_at
            .is_some_and(|t| now.saturating_duration_since(t) <= DOUBLE_CTRL_C_WINDOW)
    }

    pub fn clear_ctrl_c_arm(&mut self) {
        self.first_ctrl_c_at = None;
    }

    /// Process raw bytes read from local stdin.
    pub fn feed(&mut self, bytes: &[u8], attached: bool, now: Instant) -> Vec<FilterAction> {
        let mut actions = Vec::new();
        let mut out = Vec::new();

        let flush = |out: &mut Vec<u8>, actions: &mut Vec<FilterAction>| {
            if !out.is_empty() {
                actions.push(FilterAction::Forward(std::mem::take(out)));
            }
        };

        for &b in bytes {
            // Double Ctrl-C escape hatch while disconnected so the operator is
            // never trapped in an unreachable terminal.
            if !attached && b == 0x03 {
                self.pending_tilde = false;
                if let Some(prev) = self.first_ctrl_c_at
                    && now.saturating_duration_since(prev) <= DOUBLE_CTRL_C_WINDOW
                {
                    self.first_ctrl_c_at = None;
                    flush(&mut out, &mut actions);
                    actions.push(FilterAction::CtrlCDoubleDetach);
                    return actions;
                }
                self.first_ctrl_c_at = Some(now);
                out.push(b);
                flush(&mut out, &mut actions);
                actions.push(FilterAction::CtrlCFirstQueued);
                self.at_line_start = false;
                continue;
            }

            if self.first_ctrl_c_at.is_some() {
                self.first_ctrl_c_at = None;
            }

            if self.pending_tilde {
                self.pending_tilde = false;
                match b {
                    b'.' => {
                        flush(&mut out, &mut actions);
                        actions.push(FilterAction::Terminate);
                        return actions;
                    }
                    b'd' => {
                        flush(&mut out, &mut actions);
                        actions.push(FilterAction::Detach);
                        return actions;
                    }
                    b'?' => {
                        flush(&mut out, &mut actions);
                        actions.push(FilterAction::Help);
                        self.at_line_start = true;
                        continue;
                    }
                    b'~' => {
                        out.push(b'~');
                        self.at_line_start = false;
                        continue;
                    }
                    other => {
                        out.push(b'~');
                        out.push(other);
                        self.at_line_start = other == b'\r' || other == b'\n';
                        continue;
                    }
                }
            }

            if self.at_line_start && b == b'~' {
                self.pending_tilde = true;
                self.at_line_start = false;
                continue;
            }

            out.push(b);
            self.at_line_start = b == b'\r' || b == b'\n';
        }

        flush(&mut out, &mut actions);
        actions
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fr141_escape_sequences_and_double_ctrl_c() {
        let mut f = InputFilter::new();
        let t0 = Instant::now();

        // `~d` at start of session detaches.
        assert_eq!(f.feed(b"~d", true, t0), vec![FilterAction::Detach]);

        // Mid-line `~.` is literal text, not terminate.
        let mut f2 = InputFilter::new();
        assert_eq!(
            f2.feed(b"echo ~.\r~.", true, t0),
            vec![
                FilterAction::Forward(b"echo ~.\r".to_vec()),
                FilterAction::Terminate,
            ]
        );

        // `~~` produces one literal `~`.
        let mut f3 = InputFilter::new();
        assert_eq!(
            f3.feed(b"~~hi", true, t0),
            vec![FilterAction::Forward(b"~hi".to_vec())]
        );

        // Disconnected double Ctrl-C: 1st queues ^C + warns, 2nd within 1.5s detaches!
        let mut f4 = InputFilter::new();
        let first = f4.feed(&[0x03], false, t0);
        assert_eq!(
            first,
            vec![
                FilterAction::Forward(vec![0x03]),
                FilterAction::CtrlCFirstQueued,
            ]
        );
        assert!(f4.is_ctrl_c_armed(t0 + Duration::from_millis(500)));
        let second = f4.feed(&[0x03], false, t0 + Duration::from_millis(600));
        assert_eq!(second, vec![FilterAction::CtrlCDoubleDetach]);
    }
}
