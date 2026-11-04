// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Newline-delimited input, bounded and cancel-safe — the harness's stdout
//! (stream-json) and the toolbelt's socket (MCP over stdio framing) are both
//! read this way.

use tokio::io::AsyncBufRead;
use tokio::io::AsyncBufReadExt;

/// Lines from a stream, bounded and CANCEL-SAFE: everything consumed from the
/// stream stays in `self` until a whole line is handed out, so another arm
/// winning a `select!` mid-line costs nothing. A line longer than `max` is
/// consumed and handed out empty — a peer writing a gigabyte without a
/// newline cannot exhaust memory.
pub(crate) struct LineReader<R> {
    inner: R,
    max: usize,
    buf: Vec<u8>,
    overlong: bool,
}

impl<R: AsyncBufRead + Unpin> LineReader<R> {
    pub(crate) fn new(inner: R, max: usize) -> Self {
        Self {
            inner,
            max,
            buf: Vec::new(),
            overlong: false,
        }
    }

    /// The next line without its newline; `None` at the end of the stream.
    pub(crate) async fn next_line(&mut self) -> std::io::Result<Option<Vec<u8>>> {
        loop {
            // The only await. Nothing is consumed before it returns, and
            // everything after it up to the next loop is synchronous.
            let chunk = self.inner.fill_buf().await?;
            if chunk.is_empty() {
                if self.buf.is_empty() && !self.overlong {
                    return Ok(None);
                }
                return Ok(Some(self.take()));
            }
            let (used, done) = match chunk.iter().position(|b| *b == b'\n') {
                Some(i) => (i + 1, true),
                None => (chunk.len(), false),
            };
            if !self.overlong {
                let body = &chunk[..if done { used - 1 } else { used }];
                if self.buf.len() + body.len() > self.max {
                    self.overlong = true;
                    self.buf = Vec::new();
                } else {
                    self.buf.extend_from_slice(body);
                }
            }
            self.inner.consume(used);
            if done {
                return Ok(Some(self.take()));
            }
        }
    }

    fn take(&mut self) -> Vec<u8> {
        let line = if self.overlong {
            Vec::new()
        } else {
            std::mem::take(&mut self.buf)
        };
        self.buf.clear();
        self.overlong = false;
        line
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::io::{AsyncWriteExt, BufReader};

    use super::*;

    /// Lines are split on newlines, an overlong one comes back empty, and a
    /// read cancelled mid-line loses nothing.
    #[tokio::test]
    async fn the_line_reader_is_bounded_and_cancel_safe() {
        const MAX: usize = 1024;
        let mut data: Vec<u8> = b"one\ntwo\n".to_vec();
        data.extend(std::iter::repeat_n(b'x', MAX + 10));
        data.extend(b"\nthree");
        let mut r = LineReader::new(BufReader::new(&data[..]), MAX);
        let mut got = Vec::new();
        while let Some(line) = r.next_line().await.unwrap() {
            got.push(String::from_utf8(line).unwrap());
        }
        assert_eq!(got, ["one", "two", "", "three"]);

        // Half a line, a cancelled read, then the rest: one whole line.
        let (mut w, rd) = tokio::io::duplex(64);
        let mut r = LineReader::new(BufReader::new(rd), MAX);
        w.write_all(b"{\"type\":").await.unwrap();
        let cancelled = tokio::time::timeout(Duration::from_millis(50), r.next_line()).await;
        assert!(cancelled.is_err(), "no newline yet");
        w.write_all(b"\"x\"}\n").await.unwrap();
        assert_eq!(
            r.next_line().await.unwrap().unwrap(),
            b"{\"type\":\"x\"}".to_vec()
        );
    }
}
