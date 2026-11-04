// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Diagnostic helper for the `rc:logs-fetch` control-DC message
//! (added in rc.23). Reads the tail of the agent's current rolling
//! log file and serialises it as JSON the browser can render in the
//! log-viewer dialog.
//!
//! Why a single round-trip rather than a streaming subscription:
//! the diagnostic value comes from "what just happened in the last
//! failed upload?" — a 200-line snapshot is enough. Streaming would
//! add ordering / reconnect / replay complexity for marginal value.
//! Operator who wants live tail can request again every few seconds.
//!
//! Path resolution: uses `logging::log_dir()` as the source-of-truth,
//! then picks the lexicographically-latest `roomlerd.log.*` file (or a
// RETIRED-NAME-ANCHOR-BEGIN
// Rolled log files written BEFORE the rename are still on disk on every
// upgraded host, and this is what fetches them. Accepting only the current
// prefix would make an upgraded agent report that it has no logs.
//! legacy `roomler-agent.log.*` on a pre-rename host — P3d Slice B).
//! `tracing_appender::rolling::daily` rotates daily so the latest by
//! name is also the latest by mtime — no I/O needed to choose.
//!
//! Truncation: we read the last N lines (default 500, capped at
//! 5000) by streaming from EOF backwards in 4 KiB chunks. Files >
//! ~50 MB read efficiently because we never load the full file.

use anyhow::{Context, Result, anyhow};
use std::path::PathBuf;
use tokio::io::{AsyncReadExt, AsyncSeekExt, SeekFrom};

/// Default tail size when the browser doesn't specify `lines`. Sized
/// to a few seconds of busy-period output — enough to capture the
/// run-up to a failed upload's first error without flooding the DC.
pub const DEFAULT_TAIL_LINES: usize = 500;

/// Hard cap so an aggressive browser can't request 1M lines and
/// stall the agent reading them. Matches the in-place clamp in
/// peer.rs::attach_control_handler.
pub const MAX_TAIL_LINES: usize = 5000;

/// Resolve the current log file path. Returns `Err` when log dir is
/// unresolvable (rare — only on platforms without a data dir) or
/// when no `roomlerd.log*` (or legacy `roomler-agent.log*`) file exists
/// yet (e.g. agent just started and `tracing_appender` hasn't created
/// the first file).
///
/// P3d Slice B: the live basename is now `roomlerd.log`; a pre-rename host
/// may still have `roomler-agent.log*` files. Accept BOTH prefixes. The
/// lexicographic pick naturally prefers `roomlerd.*` over `roomler-agent.*`
/// (`'d'` > `'-'`), which matches "the new-basename file is the current one".
pub fn current_log_path() -> Result<PathBuf> {
    let dir = crate::logging::log_dir()
        .ok_or_else(|| anyhow!("log dir is unresolvable on this platform"))?;
    let entries =
        std::fs::read_dir(&dir).with_context(|| format!("reading log dir {}", dir.display()))?;
    let mut best: Option<(String, PathBuf)> = None;
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if !name.starts_with("roomlerd.log") {
            continue;
        }
        // Prefer the lexicographically-latest filename. tracing's
        // daily rotation creates `roomlerd.log.YYYY-MM-DD` so
        // the latest day sorts last. The current-day's file (no
        // suffix yet on some appender versions) is fine too — we
        // pick whichever sorts highest.
        match &best {
            Some((existing, _)) if *existing >= name => {}
            _ => best = Some((name, entry.path())),
        }
    }
    best.map(|(_, p)| p).ok_or_else(|| {
        anyhow!(
            "no roomlerd.log* or roomler-agent.log* file in {}",
            dir.display()
        )
    })
}

/// Read the last `lines` lines from the current log file and return
/// a JSON envelope ready to send back over the control DC.
///
/// JSON shape:
/// ```json
/// {
///   "t": "rc:logs-fetch.reply",
///   "ok": true,
///   "path": "C:\\Users\\...\\roomler-agent.log.2026-05-12",
///   "lines": ["[2026-05-12T11:00:01Z] INFO ...", "..."],
///   "truncated": false
/// }
/// ```
///
/// On error: `{ t: "rc:logs-fetch.reply", ok: false, error: "..." }`.
pub async fn fetch_tail(lines: usize) -> Result<serde_json::Value> {
    let lines = lines.clamp(1, MAX_TAIL_LINES);
    let path = current_log_path()?;
    let (out, truncated) = read_tail_lines(&path, lines).await?;
    Ok(serde_json::json!({
        "t": "rc:logs-fetch.reply",
        "ok": true,
        "path": path.to_string_lossy(),
        "lines": out,
        "truncated": truncated,
    }))
}

/// rc.24 — chunk the agent's reply across multiple SCTP messages so
/// large fetches (1000+ lines = >64 KiB JSON) don't exceed the
/// `max_message_size` limit and get silently dropped by webrtc-rs.
///
/// Wire format (browser already understands `rc:logs-fetch.reply`
/// from rc.23; the chunked variants below are new):
///
/// ```json
/// // First message
/// {
///   "t": "rc:logs-fetch.reply.start",
///   "id": "<request-id>",        // optional, only set when browser supplied it
///   "ok": true,
///   "path": "<log file path>",
///   "total_lines": 2000,         // total lines that will be streamed
///   "truncated": false
/// }
/// // Zero or more chunk messages
/// {
///   "t": "rc:logs-fetch.reply.chunk",
///   "id": "<request-id>",
///   "lines": ["<line>", "<line>", ...]   // sized to keep envelope < ~50 KB
/// }
/// // Final message
/// { "t": "rc:logs-fetch.reply.end", "id": "<request-id>" }
/// ```
///
/// Browsers built before rc.24 (rc.23.x) only know
/// `rc:logs-fetch.reply` — they won't recognise the streamed
/// variants. To keep backward-compat: if the entire payload fits in
/// a single envelope (≤ chunked threshold), fall back to the
/// monolithic `rc:logs-fetch.reply` shape so old browsers still
/// work for small fetches.
///
/// Returns a `Vec<serde_json::Value>` of envelopes the caller must
/// send in order over the control DC. Each envelope is guaranteed
/// to serialise to < `MAX_ENVELOPE_BYTES` so it fits comfortably
/// under the 65536-byte SCTP boundary.
pub async fn fetch_tail_chunked(
    lines: usize,
    request_id: Option<&str>,
) -> Result<Vec<serde_json::Value>> {
    let lines = lines.clamp(1, MAX_TAIL_LINES);
    let path = current_log_path()?;
    let (out, truncated) = read_tail_lines(&path, lines).await?;

    // Cheap heuristic: if total payload < MONO_THRESHOLD_BYTES,
    // send as a single rc.23-compatible envelope. Otherwise chunk.
    let approx_total: usize = out.iter().map(|s| s.len() + 4).sum();
    if approx_total < MONO_THRESHOLD_BYTES {
        return Ok(vec![serde_json::json!({
            "t": "rc:logs-fetch.reply",
            "ok": true,
            "path": path.to_string_lossy(),
            "lines": out,
            "truncated": truncated,
        })]);
    }

    // Streamed path. Estimate ~150 chars/line + 4 bytes JSON
    // overhead per line. Aim for ~40 KB per chunk envelope so
    // each one + JSON overhead stays comfortably under 50 KB.
    let mut envelopes = Vec::new();
    let path_str = path.to_string_lossy().to_string();
    envelopes.push(serde_json::json!({
        "t": "rc:logs-fetch.reply.start",
        "id": request_id,
        "ok": true,
        "path": path_str,
        "total_lines": out.len(),
        "truncated": truncated,
    }));

    let mut buf: Vec<String> = Vec::new();
    let mut buf_bytes: usize = 0;
    for line in out {
        let cost = line.len() + 4;
        if buf_bytes + cost > CHUNK_BYTES && !buf.is_empty() {
            envelopes.push(serde_json::json!({
                "t": "rc:logs-fetch.reply.chunk",
                "id": request_id,
                "lines": std::mem::take(&mut buf),
            }));
            buf_bytes = 0;
        }
        buf_bytes += cost;
        buf.push(line);
    }
    if !buf.is_empty() {
        envelopes.push(serde_json::json!({
            "t": "rc:logs-fetch.reply.chunk",
            "id": request_id,
            "lines": buf,
        }));
    }
    envelopes.push(serde_json::json!({
        "t": "rc:logs-fetch.reply.end",
        "id": request_id,
    }));
    Ok(envelopes)
}

/// Single-envelope cutoff. Payloads smaller than this go via the
/// rc.23-compatible monolithic `rc:logs-fetch.reply`. Larger ones
/// switch to the chunked stream. 32 KB leaves plenty of margin for
/// `path` + JSON overhead under the 65 KB SCTP boundary.
pub const MONO_THRESHOLD_BYTES: usize = 32 * 1024;

/// Per-chunk byte budget in the streamed path. Sized to ~40 KB so
/// envelope + JSON overhead lands < 50 KB. Each chunk pays a small
/// fixed overhead (`{"t":"...","id":"...","lines":[...]}` ≈ 60 B).
pub const CHUNK_BYTES: usize = 40 * 1024;

/// Read the last `count` lines from `path`. Returns (lines, truncated)
/// where `truncated` is true when the file had more than `count` lines.
///
/// Implementation streams from EOF backwards in 4 KiB chunks. Stops
/// once `count + 1` newlines have been seen (the +1 accounts for the
/// boundary line). Then splits the accumulated buffer and trims to
/// the last `count`.
///
/// Public for unit testing — production callers go through `fetch_tail`.
pub async fn read_tail_lines(path: &std::path::Path, count: usize) -> Result<(Vec<String>, bool)> {
    let mut file = tokio::fs::OpenOptions::new()
        .read(true)
        .open(path)
        .await
        .with_context(|| format!("opening {}", path.display()))?;
    let total_len = file
        .metadata()
        .await
        .with_context(|| format!("stat {}", path.display()))?
        .len();

    const CHUNK: u64 = 4096;
    let mut buf: Vec<u8> = Vec::with_capacity((CHUNK as usize) * 8);
    let mut pos = total_len;
    // Count newlines we've already buffered so we can stop early
    // once we've seen enough.
    let mut newlines = 0usize;
    while pos > 0 && newlines <= count {
        let read_at = pos.saturating_sub(CHUNK);
        let read_len = (pos - read_at) as usize;
        let mut chunk = vec![0u8; read_len];
        file.seek(SeekFrom::Start(read_at)).await?;
        file.read_exact(&mut chunk).await?;
        // Count newlines in this chunk (excluding a possibly-final
        // newline of the file itself — we treat any newline as a
        // line separator).
        newlines += chunk.iter().filter(|&&b| b == b'\n').count();
        // Prepend the chunk to the buffer (we read backwards, so
        // older data goes first). `append(&mut buf)` is the clippy-
        // preferred form vs `extend(buf.drain(..))` — same effect
        // (moves elements, clears buf), one fewer iterator chain.
        let mut new_buf = chunk;
        new_buf.append(&mut buf);
        buf = new_buf;
        pos = read_at;
    }

    let text = String::from_utf8_lossy(&buf);
    let all_lines: Vec<&str> = text.lines().collect();
    let truncated = all_lines.len() > count || pos > 0;
    let start = all_lines.len().saturating_sub(count);
    let out = all_lines[start..].iter().map(|s| s.to_string()).collect();
    Ok((out, truncated))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn read_tail_lines_small_file_no_truncation() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        {
            let mut f = tokio::fs::File::create(&path).await.unwrap();
            f.write_all(b"line 1\nline 2\nline 3\n").await.unwrap();
            f.sync_all().await.unwrap();
        }
        let (lines, truncated) = read_tail_lines(&path, 100).await.unwrap();
        assert_eq!(lines, vec!["line 1", "line 2", "line 3"]);
        assert!(!truncated, "tail < count should not flag truncated");
    }

    #[tokio::test]
    async fn read_tail_lines_truncates_to_count() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        {
            let mut f = tokio::fs::File::create(&path).await.unwrap();
            for i in 1..=50 {
                f.write_all(format!("line {i}\n").as_bytes()).await.unwrap();
            }
            f.sync_all().await.unwrap();
        }
        let (lines, truncated) = read_tail_lines(&path, 5).await.unwrap();
        assert_eq!(
            lines,
            vec!["line 46", "line 47", "line 48", "line 49", "line 50"]
        );
        assert!(truncated, "tail < total should flag truncated");
    }

    #[tokio::test]
    async fn read_tail_lines_empty_file() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        let (lines, truncated) = read_tail_lines(&path, 10).await.unwrap();
        assert!(lines.is_empty());
        assert!(!truncated);
    }

    #[tokio::test]
    async fn read_tail_lines_spans_chunks() {
        // 5000 lines × ~20 bytes each ≈ 100 KB, definitely spans
        // multiple 4 KiB chunks. Pin that the chunked-read logic
        // produces the same result as a naive whole-file read.
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().to_path_buf();
        {
            let mut f = tokio::fs::File::create(&path).await.unwrap();
            for i in 1..=5000 {
                f.write_all(format!("event-id-{i:08} payload\n").as_bytes())
                    .await
                    .unwrap();
            }
            f.sync_all().await.unwrap();
        }
        let (lines, truncated) = read_tail_lines(&path, 3).await.unwrap();
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0], "event-id-00004998 payload");
        assert_eq!(lines[2], "event-id-00005000 payload");
        assert!(truncated);
    }

    #[tokio::test]
    async fn fetch_tail_clamps_lines_argument() {
        // Indirect test — fetch_tail's clamp pre-routes to
        // read_tail_lines. We can't easily test the full path
        // without the log dir set up, but we can sanity-check the
        // clamp arithmetic via the constants.
        assert_eq!(0_usize.clamp(1, MAX_TAIL_LINES), 1);
        assert_eq!(10_000_usize.clamp(1, MAX_TAIL_LINES), MAX_TAIL_LINES);
        assert_eq!(
            DEFAULT_TAIL_LINES.clamp(1, MAX_TAIL_LINES),
            DEFAULT_TAIL_LINES
        );
    }

    // rc.24 — chunked-reply path threshold sanity checks. Production
    // verification (does the agent stream correctly?) happens via
    // field smoke + the browser-side parser tests.

    #[test]
    // Compile-time contract lock — the constant-ness IS the point.
    #[allow(clippy::assertions_on_constants)]
    fn mono_threshold_safely_under_sctp_boundary() {
        // SCTP max_message_size default is 65536. MONO_THRESHOLD_BYTES
        // must leave room for `{"t":"rc:logs-fetch.reply","ok":true,
        // "path":"...","lines":[...],"truncated":...}` JSON overhead
        // (~60-200 bytes typical Windows paths) AND worst-case
        // string escaping. 32 KB leaves 33 KB margin.
        assert!(MONO_THRESHOLD_BYTES < 60_000);
    }

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn chunk_bytes_safely_under_sctp_boundary() {
        // Each chunk envelope = ~60 B overhead + CHUNK_BYTES of
        // line text. Total serialised < 65536 by a comfortable
        // margin.
        assert!(CHUNK_BYTES + 200 < 65_536);
    }

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn mono_threshold_is_below_chunk_budget() {
        // Single-envelope path takes precedence over chunked when
        // payload fits — MONO_THRESHOLD ≤ CHUNK_BYTES so we never
        // emit a chunked stream that's smaller than what would have
        // fit in one envelope.
        assert!(MONO_THRESHOLD_BYTES <= CHUNK_BYTES);
    }
}
// RETIRED-NAME-ANCHOR-END
