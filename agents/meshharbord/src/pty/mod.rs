// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Pseudo-terminals for Roomler SSH interactive sessions (P4).
//!
//! Everything before this ran through [`crate::exec`], which buffers a
//! command's whole output to enforce its ceiling and hands it back when the
//! process ends. That is the right shape for `ssh <node> <command>` and the
//! wrong shape for a shell: an interactive session has to stream both ways,
//! immediately, with no ceiling — the output IS the interaction.
//!
//! So a PTY session deliberately does NOT go through the exec engine, and
//! therefore does not inherit its output cap or its wall-clock timeout. It
//! keeps the parts that still make sense: the identity model ([`crate::exec::RunAs`],
//! via the same `apply_run_as` every other path uses) and process teardown.
//!
//! # Two implementations, one surface
//!
//! The mechanisms have nothing in common — Unix opens a pty pair and `exec`s
//! into the slave; Windows asks the console host for a pseudoconsole and hands
//! it to `CreateProcess` through an attribute list. What they share is the
//! shape the SSH server needs, so both expose exactly:
//!
//! * [`PtyProcess::spawn`] — start a shell on a new terminal, as `run_as`
//! * [`PtyProcess::read`]  — one chunk of output; `Ok(0)` = session over
//! * [`PtyProcess::wait`]  — the exit status, in SSH's unsigned form
//! * [`PtyProcess::kill_group`] / `Drop` — nothing outlives the session
//! * [`PtyHandle::write_all`] / [`PtyHandle::resize`] — the input + control
//!   half, usable from a different task than the output pump
//!
//! `ssh.rs` therefore has ONE code path. Keeping the two platforms behind one
//! surface is deliberate: an interactive session is where a divergence would be
//! least visible and most annoying, and a per-platform SSH handler would have
//! grown two subtly different privilege and teardown stories.

#[cfg(all(unix, feature = "ssh-server"))]
mod unix;
#[cfg(all(unix, feature = "ssh-server"))]
pub use unix::{PtyHandle, PtyProcess};

#[cfg(all(windows, feature = "ssh-server"))]
mod windows;
#[cfg(all(windows, feature = "ssh-server"))]
pub use windows::{PtyHandle, PtyProcess};

/// Terminal geometry, in the order SSH sends it.
///
/// Shared because it is the one thing both platforms genuinely agree on, and
/// because the zero-clamp below is a correctness rule rather than an
/// implementation detail.
#[cfg(feature = "ssh-server")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct WinSize {
    pub cols: u16,
    pub rows: u16,
}

#[cfg(feature = "ssh-server")]
impl WinSize {
    /// Clamp to something a terminal can actually be.
    ///
    /// A client may send 0×0 (some do, when the window size is not yet known,
    /// and `ssh` with a piped stdin always does), and a zero-sized terminal
    /// makes full-screen applications misbehave in ways that look like a
    /// roomler bug. 80×24 is the conventional fallback.
    pub(crate) fn sane(self) -> Self {
        Self {
            cols: if self.cols == 0 { 80 } else { self.cols },
            rows: if self.rows == 0 { 24 } else { self.rows },
        }
    }
}

#[cfg(all(test, feature = "ssh-server"))]
mod tests {
    use super::*;

    /// A zero size is what a client sends before it knows its window — and
    /// what `ssh` sends whenever stdin is a pipe rather than a terminal.
    #[test]
    fn a_zero_geometry_falls_back_to_a_usable_terminal() {
        assert_eq!(
            WinSize { cols: 0, rows: 0 }.sane(),
            WinSize { cols: 80, rows: 24 }
        );
        assert_eq!(
            WinSize { cols: 0, rows: 40 }.sane(),
            WinSize { cols: 80, rows: 40 }
        );
        // A real size is never second-guessed.
        assert_eq!(
            WinSize {
                cols: 120,
                rows: 40
            }
            .sane(),
            WinSize {
                cols: 120,
                rows: 40
            }
        );
    }
}
