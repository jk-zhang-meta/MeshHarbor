// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Byte-offset replay ring, exactly-once c2s input queue/dedup, escape/UTF-8
//! ground-state tracker, and VT100 snapshot/shadow screen engine.

use std::collections::VecDeque;
use std::panic::{AssertUnwindSafe, catch_unwind};

use super::{MAX_C2S_QUEUE_BYTES, VT_SCROLLBACK_LEN, clamp_dims};

/// Circular byte-offset replay buffer (default 4 MiB).
///
/// Tracks absolute stream offsets `[base_offset .. head_offset)`. If a resuming
/// client's `last_rx >= base_offset`, exact byte-for-byte replay is guaranteed
/// with zero UTF-8 or ANSI escape boundary issues.
#[derive(Debug, Clone)]
pub struct ByteRing {
    buf: VecDeque<u8>,
    capacity: usize,
    base_offset: u64,
    head_offset: u64,
}

impl ByteRing {
    pub fn new(capacity: usize) -> Self {
        let cap = capacity.max(4096);
        Self {
            buf: VecDeque::with_capacity(cap.min(65536)),
            capacity: cap,
            base_offset: 0,
            head_offset: 0,
        }
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn base_offset(&self) -> u64 {
        self.base_offset
    }

    pub fn head_offset(&self) -> u64 {
        self.head_offset
    }

    /// Append bytes and return the starting offset assigned to `data`.
    pub fn push(&mut self, data: &[u8]) -> u64 {
        let start = self.head_offset;
        if data.is_empty() {
            return start;
        }
        if data.len() >= self.capacity {
            let keep = &data[data.len() - self.capacity..];
            self.buf.clear();
            self.buf.extend(keep.iter().copied());
            self.head_offset = self.head_offset.saturating_add(data.len() as u64);
            self.base_offset = self.head_offset.saturating_sub(self.capacity as u64);
            return start;
        }
        let overflow = (self.buf.len() + data.len()).saturating_sub(self.capacity);
        if overflow > 0 {
            self.buf.drain(..overflow);
            self.base_offset = self.base_offset.saturating_add(overflow as u64);
        }
        self.buf.extend(data.iter().copied());
        self.head_offset = self.head_offset.saturating_add(data.len() as u64);
        start
    }

    /// True if all bytes from `from_offset..head_offset` are still in the ring.
    pub fn can_replay_from(&self, from_offset: u64) -> bool {
        from_offset >= self.base_offset && from_offset <= self.head_offset
    }

    /// Number of unreplayable bytes missed if `from_offset < base_offset`.
    pub fn gap_from(&self, from_offset: u64) -> u64 {
        self.base_offset.saturating_sub(from_offset)
    }

    /// Copy all buffered bytes from `from_offset..head_offset`.
    /// Returns `None` if `from_offset < base_offset` (ring overflowed) or
    /// `from_offset > head_offset` (client offset ahead of host).
    pub fn read_from(&self, from_offset: u64) -> Option<Vec<u8>> {
        if !self.can_replay_from(from_offset) {
            return None;
        }
        let skip = (from_offset - self.base_offset) as usize;
        let len = self.buf.len().saturating_sub(skip);
        let mut out = Vec::with_capacity(len);
        let (a, b) = self.buf.as_slices();
        if skip < a.len() {
            out.extend_from_slice(&a[skip..]);
            out.extend_from_slice(b);
        } else {
            out.extend_from_slice(&b[skip - a.len()..]);
        }
        Some(out)
    }
}

/// Client-side unacknowledged input queue (capped at 64 KiB) enabling
/// exactly-once delivery across disconnects and reconnects.
#[derive(Debug, Clone)]
pub struct C2sClientQueue {
    acked_seq: u64,
    next_seq: u64,
    max_bytes: usize,
    buf: VecDeque<u8>,
}

impl Default for C2sClientQueue {
    fn default() -> Self {
        Self::new(MAX_C2S_QUEUE_BYTES)
    }
}

impl C2sClientQueue {
    pub fn new(max_bytes: usize) -> Self {
        Self {
            acked_seq: 0,
            next_seq: 0,
            max_bytes: max_bytes.max(1024),
            buf: VecDeque::new(),
        }
    }

    pub fn acked_seq(&self) -> u64 {
        self.acked_seq
    }

    pub fn next_seq(&self) -> u64 {
        self.next_seq
    }

    pub fn buffered_len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_full(&self) -> bool {
        self.buf.len() >= self.max_bytes
    }

    /// Enqueue newly typed input bytes, returning `(seq, accepted_bytes)`.
    /// Returns `None` if the queue is at capacity.
    pub fn push(&mut self, data: &[u8]) -> Option<(u64, Vec<u8>)> {
        if data.is_empty() {
            return None;
        }
        let avail = self.max_bytes.saturating_sub(self.buf.len());
        if avail == 0 {
            return None;
        }
        let take = data.len().min(avail);
        let slice = &data[..take];
        let seq = self.next_seq;
        self.buf.extend(slice.iter().copied());
        self.next_seq = self.next_seq.saturating_add(take as u64);
        Some((seq, slice.to_vec()))
    }

    /// Advance cumulative ACK watermark, discarding confirmed input bytes.
    pub fn ack(&mut self, upto: u64) {
        let clamped = upto.min(self.next_seq);
        if clamped <= self.acked_seq {
            return;
        }
        let drop_n = (clamped - self.acked_seq) as usize;
        let actual = drop_n.min(self.buf.len());
        self.buf.drain(..actual);
        self.acked_seq = clamped;
    }

    /// Rebase a cold-reattaching CLI process's sequence numbers to the host's
    /// reported `c2s_acked` so newly typed input (and any bytes typed locally
    /// while waiting for cold reattach) starts strictly at `seq` instead of 0.
    pub fn rebase(&mut self, seq: u64) {
        self.acked_seq = seq;
        self.next_seq = seq.saturating_add(self.buf.len() as u64);
    }

    /// Return all unacknowledged bytes split into `(seq, chunk)` pairs <= `max_chunk`.
    pub fn unacked_chunks(&self, max_chunk: usize) -> Vec<(u64, Vec<u8>)> {
        let step = max_chunk.max(1);
        let mut all = Vec::with_capacity(self.buf.len());
        let (a, b) = self.buf.as_slices();
        all.extend_from_slice(a);
        all.extend_from_slice(b);

        let mut out = Vec::new();
        let mut seq = self.acked_seq;
        for chunk in all.chunks(step) {
            out.push((seq, chunk.to_vec()));
            seq = seq.saturating_add(chunk.len() as u64);
        }
        out
    }

    /// Remove a trailing queued Ctrl-C (`0x03`) when the user double-presses
    /// Ctrl-C while disconnected to detach locally without sending an unintended
    /// interrupt on future reattach.
    pub fn drop_trailing_ctrl_c(&mut self) -> bool {
        if self.buf.back() == Some(&0x03) {
            self.buf.pop_back();
            self.next_seq = self.next_seq.saturating_sub(1);
            true
        } else {
            false
        }
    }
}

/// Host-side input deduplicator guaranteeing exactly-once writes to the PTY.
#[derive(Debug, Default, Clone)]
pub struct C2sHostDedup {
    next_expected: u64,
}

impl C2sHostDedup {
    pub fn new() -> Self {
        Self { next_expected: 0 }
    }

    pub fn next_expected(&self) -> u64 {
        self.next_expected
    }

    /// Given a client `Data{seq, data}` frame, returns the slice that has NOT
    /// yet been written to the PTY and advances `next_expected`.
    /// Out-of-order future gaps (`seq > next_expected`) return an empty slice
    /// without advancing (TCP-ordered transport guarantees sequential replay).
    pub fn accept<'a>(&mut self, seq: u64, data: &'a [u8]) -> &'a [u8] {
        if data.is_empty() || seq > self.next_expected {
            return &[];
        }
        let end = seq.saturating_add(data.len() as u64);
        if end <= self.next_expected {
            return &[];
        }
        let skip = (self.next_expected - seq) as usize;
        let fresh = &data[skip..];
        self.next_expected = end;
        fresh
    }
}

/// Tracks raw bytes since the last clean ANSI/UTF-8 ground state (capped at 64 KiB)
/// so a snapshot taken mid-escape-sequence can append the exact partial bytes
/// and live bytes arriving after `at_seq` finish the sequence cleanly.
#[derive(Debug, Clone)]
pub struct GroundStateTracker {
    state: ParseState,
    pending: Vec<u8>,
    max_pending: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ParseState {
    Ground,
    Utf8(u8),
    Esc,
    EscIntermediate,
    Csi,
    Osc,
    OscEsc,
    StringSeq,
    StringEsc,
}

impl Default for GroundStateTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl GroundStateTracker {
    pub fn new() -> Self {
        Self {
            state: ParseState::Ground,
            pending: Vec::new(),
            max_pending: 64 * 1024,
        }
    }

    pub fn is_ground(&self) -> bool {
        self.state == ParseState::Ground
    }

    /// Raw incomplete UTF-8 or escape sequence bytes since the last ground state.
    pub fn pending_bytes(&self) -> &[u8] {
        &self.pending
    }

    pub fn process(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.step(b);
        }
    }

    fn step(&mut self, b: u8) {
        match self.state {
            ParseState::Ground => {
                if b == 0x1b {
                    self.pending.clear();
                    self.pending.push(b);
                    self.state = ParseState::Esc;
                } else if (0xC2..=0xDF).contains(&b) {
                    self.pending.clear();
                    self.pending.push(b);
                    self.state = ParseState::Utf8(1);
                } else if (0xE0..=0xEF).contains(&b) {
                    self.pending.clear();
                    self.pending.push(b);
                    self.state = ParseState::Utf8(2);
                } else if (0xF0..=0xF4).contains(&b) {
                    self.pending.clear();
                    self.pending.push(b);
                    self.state = ParseState::Utf8(3);
                }
            }
            ParseState::Utf8(rem) => {
                if (b & 0xC0) == 0x80 {
                    self.push_pending(b);
                    if rem <= 1 {
                        self.reset_ground();
                    } else {
                        self.state = ParseState::Utf8(rem - 1);
                    }
                } else {
                    self.reset_ground();
                    self.step(b);
                }
            }
            ParseState::Esc => {
                self.push_pending(b);
                match b {
                    b'[' => self.state = ParseState::Csi,
                    b']' => self.state = ParseState::Osc,
                    b'P' | b'^' | b'_' => self.state = ParseState::StringSeq,
                    0x20..=0x2F => self.state = ParseState::EscIntermediate,
                    0x1b => {
                        self.pending.clear();
                        self.pending.push(b);
                    }
                    _ => self.reset_ground(),
                }
            }
            ParseState::EscIntermediate => {
                self.push_pending(b);
                if !(0x20..=0x2F).contains(&b) {
                    self.reset_ground();
                }
            }
            ParseState::Csi => {
                self.push_pending(b);
                if (0x40..=0x7E).contains(&b) {
                    self.reset_ground();
                } else if b == 0x1b {
                    self.pending.clear();
                    self.pending.push(b);
                    self.state = ParseState::Esc;
                }
            }
            ParseState::Osc => {
                self.push_pending(b);
                if b == 0x07 {
                    self.reset_ground();
                } else if b == 0x1b {
                    self.state = ParseState::OscEsc;
                }
            }
            ParseState::OscEsc => {
                self.push_pending(b);
                if b == b'\\' {
                    self.reset_ground();
                } else if b != 0x1b {
                    self.state = ParseState::Osc;
                }
            }
            ParseState::StringSeq => {
                self.push_pending(b);
                if b == 0x1b {
                    self.state = ParseState::StringEsc;
                }
            }
            ParseState::StringEsc => {
                self.push_pending(b);
                if b == b'\\' {
                    self.reset_ground();
                } else if b != 0x1b {
                    self.state = ParseState::StringSeq;
                }
            }
        }
    }

    fn push_pending(&mut self, b: u8) {
        if self.pending.len() < self.max_pending {
            self.pending.push(b);
        } else {
            self.reset_ground();
        }
    }

    fn reset_ground(&mut self) {
        self.pending.clear();
        self.state = ParseState::Ground;
    }
}

/// Safe `vt100::Parser` wrapper used on both:
/// - Target `ssh-pty-host` (for >4 MiB ring overflow snapshot fallback)
/// - Client `mh ssh` (shadow screen for non-corrupting top-row reconnect overlay)
///
/// Every call into `vt100` is guarded with `catch_unwind`; an unexpected parser
/// panic disables snapshots for that session only and never crashes the session.
pub struct VtScreenTracker {
    parser: Option<vt100::Parser>,
    ground: GroundStateTracker,
    cols: u16,
    rows: u16,
}

impl VtScreenTracker {
    pub fn new(cols: u16, rows: u16, scrollback_len: usize) -> Self {
        let (cols, rows) = clamp_dims(cols, rows);
        let sb = scrollback_len.min(VT_SCROLLBACK_LEN);
        Self {
            parser: Some(vt100::Parser::new(rows, cols, sb)),
            ground: GroundStateTracker::new(),
            cols,
            rows,
        }
    }

    pub fn size(&self) -> (u16, u16) {
        (self.cols, self.rows)
    }

    pub fn is_healthy(&self) -> bool {
        self.parser.is_some()
    }

    pub fn process(&mut self, bytes: &[u8]) {
        self.ground.process(bytes);
        let Some(ref mut p) = self.parser else {
            return;
        };
        if catch_unwind(AssertUnwindSafe(|| p.process(bytes))).is_err() {
            self.parser = None;
        }
    }

    pub fn resize(&mut self, cols: u16, rows: u16) {
        let (cols, rows) = clamp_dims(cols, rows);
        self.cols = cols;
        self.rows = rows;
        let Some(ref mut p) = self.parser else {
            return;
        };
        if catch_unwind(AssertUnwindSafe(|| p.screen_mut().set_size(rows, cols))).is_err() {
            self.parser = None;
        }
    }

    pub fn is_alternate_screen(&self) -> bool {
        self.parser
            .as_ref()
            .is_some_and(|p| p.screen().alternate_screen())
    }

    /// Build a complete ANSI snapshot payload that restores the terminal to the
    /// exact state at `at_seq`, including a dim gap marker on the primary screen
    /// when `gap_bytes > 0` and any partial escape/UTF-8 suffix from `ground`.
    pub fn build_snapshot(&mut self, gap_bytes: u64, offline_secs: u64) -> Option<Vec<u8>> {
        let p = self.parser.as_ref()?;
        let res = catch_unwind(AssertUnwindSafe(|| {
            let screen = p.screen();
            let alt = screen.alternate_screen();
            let mut out = Vec::new();
            // Reset any stray client attributes/scroll regions cleanly first.
            out.extend_from_slice(b"\x1b[0m\x1b[r");
            if !alt && gap_bytes > 0 {
                let mb = (gap_bytes as f64) / (1024.0 * 1024.0);
                let dur = format_offline_duration(offline_secs);
                let notice = format!(
                    "\r\n\x1b[2m── meshharbor: {mb:.1} MB not replayed (offline {dur}) ──\x1b[0m\r\n"
                );
                out.extend_from_slice(notice.as_bytes());
            }
            out.extend_from_slice(&screen.state_formatted());
            // Append any incomplete UTF-8 or escape sequence since last ground state.
            out.extend_from_slice(self.ground.pending_bytes());
            out
        }));
        match res {
            Ok(bytes) => Some(bytes),
            Err(_) => {
                self.parser = None;
                None
            }
        }
    }

    /// Render the ANSI sequence needed to repaint row 0 (top row) from the
    /// client-side shadow screen and return the cursor to its true position
    /// and visibility state — erases our reconnect status bar with zero artifacts.
    pub fn render_top_row_restore(&mut self) -> Option<Vec<u8>> {
        let p = self.parser.as_ref()?;
        let res = catch_unwind(AssertUnwindSafe(|| {
            let screen = p.screen();
            let (rows, cols) = screen.size();
            if rows == 0 || cols == 0 {
                return Vec::new();
            }
            let (cur_row, cur_col) = screen.cursor_position();
            let hide = screen.hide_cursor();
            let mut out = Vec::new();
            // Hide cursor during repaint, jump to 1;1, clear line, paint shadow row 0.
            out.extend_from_slice(b"\x1b[?25l\x1b[1;1H\x1b[0m\x1b[2K");
            if let Some(first_row) = screen.rows_formatted(0, cols).next() {
                out.extend_from_slice(&first_row);
            }
            // Restore attributes and exact cursor location (1-based CUP).
            out.extend_from_slice(
                format!("\x1b[0m\x1b[{};{}H", cur_row.saturating_add(1), cur_col.saturating_add(1))
                    .as_bytes(),
            );
            if !hide {
                out.extend_from_slice(b"\x1b[?25h");
            }
            out
        }));
        match res {
            Ok(bytes) => Some(bytes),
            Err(_) => {
                self.parser = None;
                None
            }
        }
    }

    /// Extract visible screen text lines (primarily for deterministic convergence tests).
    pub fn contents(&self) -> Option<String> {
        self.parser.as_ref().map(|p| p.screen().contents())
    }
}

fn format_offline_duration(secs: u64) -> String {
    if secs < 60 {
        format!("{secs}s")
    } else if secs < 3600 {
        format!("{}m{}s", secs / 60, secs % 60)
    } else {
        format!("{}h{}m", secs / 3600, (secs % 3600) / 60)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fr141_byte_ring_exact_replay_and_overflow_detection() {
        let mut ring = ByteRing::new(4096);
        let mut expected = Vec::new();
        for i in 0..10u32 {
            let chunk = format!("line-{i:04}-payload\n");
            let off = ring.push(chunk.as_bytes());
            assert_eq!(off, expected.len() as u64);
            expected.extend_from_slice(chunk.as_bytes());
        }
        assert!(ring.can_replay_from(0));
        assert_eq!(ring.read_from(0).unwrap(), expected);
        assert_eq!(ring.read_from(17).unwrap(), expected[17..]);
        assert_eq!(ring.read_from(expected.len() as u64).unwrap(), Vec::<u8>::new());

        // Push 8 KiB to force wrap-around beyond 4096.
        let big = vec![b'A'; 8192];
        ring.push(&big);
        assert!(!ring.can_replay_from(0));
        assert!(ring.gap_from(0) > 0);
        assert!(ring.read_from(0).is_none());
        let base = ring.base_offset();
        let tail = ring.read_from(base).unwrap();
        assert_eq!(tail.len(), 4096);
        assert!(tail.iter().all(|&b| b == b'A'));
    }

    #[test]
    fn fr141_c2s_queue_and_dedup_exactly_once() {
        let mut cli = C2sClientQueue::new(1024);
        let mut host = C2sHostDedup::new();
        let mut applied = Vec::new();

        let (s1, b1) = cli.push(b"echo hi\n").unwrap();
        let (s2, b2) = cli.push(b"ls -la\n").unwrap();

        // First chunk lands cleanly.
        applied.extend_from_slice(host.accept(s1, &b1));
        // Simulate disconnect BEFORE client receives Ack for s1.
        // Client retransmits BOTH unacked chunks on reconnect.
        for (seq, chunk) in cli.unacked_chunks(4) {
            applied.extend_from_slice(host.accept(seq, &chunk));
        }
        // Host reports c2s_acked = next_expected.
        cli.ack(host.next_expected());
        assert_eq!(cli.buffered_len(), 0);
        assert_eq!(applied, b"echo hi\nls -la\n");

        // Extra duplicate retransmission is a no-op.
        assert!(host.accept(s2, &b2).is_empty());

        // Double Ctrl-C discards trailing 0x03.
        cli.push(&[0x03]).unwrap();
        assert!(cli.drop_trailing_ctrl_c());
        assert_eq!(cli.buffered_len(), 0);

        // Cold `--resume` process starts at 0, buffers pre-attach input, then
        // rebases to host's `c2s_acked` without losing a single byte!
        let mut cold_cli = C2sClientQueue::new(1024);
        cold_cli.push(b"pwd\n").unwrap();
        cold_cli.rebase(host.next_expected());
        let mut cold_applied = Vec::new();
        for (seq, chunk) in cold_cli.unacked_chunks(16) {
            cold_applied.extend_from_slice(host.accept(seq, &chunk));
        }
        assert_eq!(cold_applied, b"pwd\n");
        cold_cli.ack(host.next_expected());
        assert_eq!(cold_cli.buffered_len(), 0);
    }

    #[test]
    fn fr141_ground_state_and_vt_snapshot_convergence() {
        let mut host_vt = VtScreenTracker::new(80, 24, 100);
        // Feed styled text plus a split CSI escape sequence across snapshot boundary.
        let part1 = b"\x1b[2J\x1b[1;1H\x1b[32mREADY\x1b[0m\r\nRow 2: \x1b[31";
        let part2 = b"mRED\x1b[0m";
        host_vt.process(part1);
        assert!(!host_vt.ground.is_ground());
        assert_eq!(host_vt.ground.pending_bytes(), b"\x1b[31");

        let snap = host_vt.build_snapshot(0, 0).expect("snapshot");
        host_vt.process(part2);

        // A fresh client receives the snapshot followed by part2 and converges identically.
        let mut client_vt = VtScreenTracker::new(80, 24, 100);
        client_vt.process(&snap);
        client_vt.process(part2);
        assert_eq!(client_vt.contents(), host_vt.contents());

        // Top-row restore returns non-empty repaint sequence.
        let restore = client_vt.render_top_row_restore().expect("restore");
        assert!(!restore.is_empty());
    }
}
