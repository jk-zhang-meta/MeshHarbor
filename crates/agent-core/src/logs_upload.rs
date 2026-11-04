// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! rc.58 — centralized log uploader.
//!
//! A `tracing-subscriber::Layer` that captures every emitted event,
//! converts it into a [`LogLine`], and forwards it to a tokio mpsc
//! channel. A background task drains the channel every 5 s and POSTs
//! batches of up to 500 lines to
//! `POST /api/tenant/{tenant_id}/agent/{agent_id}/logs` (auth: agent
//! JWT).
//!
//! Default ON. Kill switch: `ROOMLERD_LOGS_UPLOAD_DISABLED=1`.
//!
//! Failure modes:
//! - Channel full (uploader too slow / network dead) → newest events
//!   dropped at the layer (`try_send` returns Err). Acceptable for
//!   diagnostic data; the rolling on-disk file logs retain everything.
//! - 401 / 403 from server → batch dropped, longer backoff (likely
//!   JWT expired / agent unenrolled).
//! - #2512: the control socket heard the server refuse this enrollment's
//!   token → nothing is posted (batches held, shed when full) until a new
//!   token or the socket's next accepted upgrade.
//! - Other transient failures → batch retained, exponential backoff
//!   capped at 60 s.

use bson::{DateTime, Document};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

// Wire types — mirror the shape in `crates/db/src/models/agent_log.rs`
// so the agent doesn't need a `meshharbor-db` dependency (which would
// drag the MongoDB driver into the agent binary). Serde reps below
// MUST stay in sync with the db-side types; the integration test
// `crates/tests/src/agent_log.rs` will lock both.

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "UPPERCASE")]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LogSource {
    Agent,
    Service,
    Installer,
    Crash,
    Updater,
    Browser,
}

impl LogSource {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Agent => "agent",
            Self::Service => "service",
            Self::Installer => "installer",
            Self::Crash => "crash",
            Self::Updater => "updater",
            Self::Browser => "browser",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogLine {
    pub ts: DateTime,
    pub level: LogLevel,
    pub target: String,
    pub msg: String,
    #[serde(default, skip_serializing_if = "Document::is_empty")]
    pub fields: Document,
}
use tokio::sync::mpsc;
use tracing::Subscriber;
use tracing_subscriber::Layer;
use tracing_subscriber::layer::Context;
use tracing_subscriber::registry::LookupSpan;

/// Channel capacity. ~10 000 lines × ~200 B = ~2 MB of in-memory
/// backpressure before the layer starts dropping events. Sized to
/// survive ~8 minutes of busy-session log volume (20 lines/sec) if
/// the network is dead, then degrade gracefully.
pub const CHANNEL_CAPACITY: usize = 10_000;

/// Flush cadence. Every N seconds the uploader drains the channel up
/// to [`MAX_BATCH_LINES`] and posts a batch.
pub const FLUSH_INTERVAL_SECS: u64 = 5;

/// Per-batch line cap. Matches the server-side
/// `AgentLogBatch::MAX_LINES_PER_BATCH` so a batch never gets rejected
/// for being too large.
pub const MAX_BATCH_LINES: usize = 500;

/// Initial retry delay on transient upload failure. Doubles on each
/// failure up to [`MAX_RETRY_BACKOFF_SECS`], resets on success.
pub const INITIAL_RETRY_BACKOFF_SECS: u64 = 5;

pub const MAX_RETRY_BACKOFF_SECS: u64 = 60;

/// Tracing layer that captures events and forwards them to the
/// uploader task via an mpsc channel. Construct with [`new`] which
/// returns the layer + the consumer end of the channel; pass the
/// receiver into [`run_uploader`] once config is loaded.
pub struct LogUploadLayer {
    tx: mpsc::Sender<LogLine>,
}

impl LogUploadLayer {
    /// Construct a layer + receiver pair. Receiver is given to the
    /// background uploader task; if no uploader is started, the layer
    /// silently drops events when the channel fills.
    pub fn new() -> (Self, mpsc::Receiver<LogLine>) {
        let (tx, rx) = mpsc::channel(CHANNEL_CAPACITY);
        (Self { tx }, rx)
    }
}

impl<S> Layer<S> for LogUploadLayer
where
    S: Subscriber + for<'a> LookupSpan<'a>,
{
    fn on_event(&self, event: &tracing::Event<'_>, _ctx: Context<'_, S>) {
        let metadata = event.metadata();
        let level = match *metadata.level() {
            tracing::Level::TRACE => LogLevel::Trace,
            tracing::Level::DEBUG => LogLevel::Debug,
            tracing::Level::INFO => LogLevel::Info,
            tracing::Level::WARN => LogLevel::Warn,
            tracing::Level::ERROR => LogLevel::Error,
        };
        let target = metadata.target().to_string();

        // Skip our own uploader's failure logs to avoid feedback loops
        // ("upload failed" → another event → "upload failed" → ...).
        // Target prefix matches this module's tracing::span! site.
        if target == "meshharbord::logs_upload" {
            return;
        }

        let mut visitor = FieldVisitor::default();
        event.record(&mut visitor);

        let line = LogLine {
            ts: DateTime::now(),
            level,
            target,
            msg: visitor.message,
            fields: visitor.fields,
        };
        // Non-blocking send — drop on full channel. The on-disk file
        // log retains everything regardless.
        let _ = self.tx.try_send(line);
    }
}

/// Visitor that splits a tracing event's fields into the conventional
/// `message` (the `"some literal {}"` interpolated arg) plus the
/// structured key=value pairs.
#[derive(Default)]
struct FieldVisitor {
    message: String,
    fields: Document,
}

impl tracing::field::Visit for FieldVisitor {
    fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
        let name = field.name();
        let s = format!("{value:?}");
        if name == "message" {
            // tracing wraps Debug output in quotes for &str; strip them
            // so the persisted msg matches the visible log line.
            self.message = strip_outer_quotes(&s);
        } else {
            self.fields.insert(name, s);
        }
    }
    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        if field.name() == "message" {
            self.message = value.to_string();
        } else {
            self.fields.insert(field.name(), value.to_string());
        }
    }
    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        self.fields.insert(field.name(), value);
    }
    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        // BSON i64 is the closest fit; clamp on overflow to keep the
        // round-trip lossless for the common case (Unix timestamps,
        // byte counts under 2^63).
        let v = if value <= i64::MAX as u64 {
            value as i64
        } else {
            i64::MAX
        };
        self.fields.insert(field.name(), v);
    }
    fn record_f64(&mut self, field: &tracing::field::Field, value: f64) {
        self.fields.insert(field.name(), value);
    }
    fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
        self.fields.insert(field.name(), value);
    }
}

fn strip_outer_quotes(s: &str) -> String {
    if s.len() >= 2 && s.starts_with('"') && s.ends_with('"') {
        s[1..s.len() - 1].to_string()
    } else {
        s.to_string()
    }
}

/// Configuration captured AFTER the agent config is loaded. Held by
/// the uploader task for the life of the process.
#[derive(Debug, Clone)]
pub struct UploadConfig {
    pub server_url: String,
    pub tenant_id: String,
    pub agent_id: String,
    /// FR-103 — the enrollment's LIVE token, read per batch, so a renewal
    /// reaches the uploader without a restart.
    pub agent_jwt: crate::token_slot::TokenSlot,
    pub agent_version: String,
    pub host_id_hash: String,
    pub source: LogSource,
}

/// The uploader's clock: [`Pace::PRODUCTION`], or a fast one in a test.
#[derive(Debug, Clone, Copy)]
struct Pace {
    flush: std::time::Duration,
    initial_backoff: std::time::Duration,
    max_backoff: std::time::Duration,
}

impl Pace {
    const PRODUCTION: Pace = Pace {
        flush: std::time::Duration::from_secs(FLUSH_INTERVAL_SECS),
        initial_backoff: std::time::Duration::from_secs(INITIAL_RETRY_BACKOFF_SECS),
        max_backoff: std::time::Duration::from_secs(MAX_RETRY_BACKOFF_SECS),
    };
}

/// Long-running task: drain the channel every [`FLUSH_INTERVAL_SECS`]
/// and POST batches up to [`MAX_BATCH_LINES`] lines.
///
/// Exits cleanly when the layer is dropped (channel closes).
pub async fn run_uploader(rx: mpsc::Receiver<LogLine>, config: UploadConfig) {
    run_uploader_paced(rx, config, Pace::PRODUCTION).await
}

async fn run_uploader_paced(mut rx: mpsc::Receiver<LogLine>, config: UploadConfig, pace: Pace) {
    let client = match reqwest::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            // Without a client we can't upload anything. Drain the
            // channel forever so the layer doesn't backpressure.
            tracing::warn!(target: "meshharbord::logs_upload", %e, "reqwest client build failed; logs upload disabled");
            while rx.recv().await.is_some() {}
            return;
        }
    };
    let url = format!(
        "{}/api/tenant/{}/agent/{}/logs",
        config.server_url.trim_end_matches('/'),
        config.tenant_id,
        config.agent_id,
    );
    let mut buf: Vec<LogLine> = Vec::with_capacity(MAX_BATCH_LINES);
    let mut backoff = pace.initial_backoff;

    loop {
        tokio::time::sleep(pace.flush).await;

        // Drain up to MAX_BATCH_LINES from the channel without
        // blocking on an empty channel.
        let mut closed = false;
        while buf.len() < MAX_BATCH_LINES {
            match rx.try_recv() {
                Ok(line) => buf.push(line),
                Err(mpsc::error::TryRecvError::Empty) => break,
                Err(mpsc::error::TryRecvError::Disconnected) => {
                    closed = true;
                    break;
                }
            }
        }
        if buf.is_empty() {
            if closed {
                return;
            }
            continue;
        }

        // #2512 — the server refuses this enrollment's token, as the control
        // socket heard it (`TokenSlot::is_refused`). A POST now is one it
        // will only 401, and a device whose row was gone posted every 5 s,
        // forever. Hold the batch (shedding as below) until a new token or
        // the socket's next accepted upgrade.
        if config.agent_jwt.is_refused() {
            if closed {
                return;
            }
            shed_oldest_half_if_full(&mut buf);
            continue;
        }

        let payload = serde_json::json!({
            "source": config.source.as_str(),
            "agent_version": config.agent_version,
            "host_id_hash": config.host_id_hash,
            "lines": &buf,
        });

        let send = client
            .post(&url)
            .bearer_auth(config.agent_jwt.get())
            .json(&payload)
            .send()
            .await;

        match send {
            Ok(resp) if resp.status().is_success() => {
                buf.clear();
                backoff = pace.initial_backoff;
            }
            Ok(resp)
                if resp.status() == reqwest::StatusCode::UNAUTHORIZED
                    || resp.status() == reqwest::StatusCode::FORBIDDEN =>
            {
                // Permanent for this JWT — drop the batch to free buf.
                // Common cause: agent unenrolled or token rotated.
                buf.clear();
                // #2512 — and wait the long backoff out, as the module doc
                // promises. This arm used to set it and go straight back to
                // the flush tick, so nothing ever waited on it.
                backoff = pace.max_backoff;
                tokio::time::sleep(backoff.saturating_sub(pace.flush)).await;
            }
            Ok(resp) => {
                // Other non-success (500, 422, etc.) — keep batch, backoff.
                // 422 means the server rejected our shape; logging it at
                // WARN lets us spot persistent malformed batches without
                // a tight retry loop.
                let status = resp.status();
                tracing::warn!(target: "meshharbord::logs_upload", %status, "logs upload non-success");
                tokio::time::sleep(backoff.saturating_sub(pace.flush)).await;
                backoff = (backoff * 2).min(pace.max_backoff);
            }
            Err(e) => {
                // Transport-level failure (DNS / connect / timeout) —
                // keep batch, backoff. Don't log every time: that would
                // re-fire on every tick when offline. Suppress to
                // tracing::debug so the rolling log stays useful but
                // doesn't flood.
                tracing::debug!(target: "meshharbord::logs_upload", %e, "logs upload error");
                tokio::time::sleep(backoff.saturating_sub(pace.flush)).await;
                backoff = (backoff * 2).min(pace.max_backoff);
            }
        }

        shed_oldest_half_if_full(&mut buf);
    }
}

/// If the batch hits the cap after a failure (the queue keeps growing),
/// shed the oldest half so the buf doesn't grow unboundedly. Lost diagnostic
/// data is preferable to OOM.
fn shed_oldest_half_if_full(buf: &mut Vec<LogLine>) {
    if buf.len() >= MAX_BATCH_LINES {
        let drop_n = buf.len() / 2;
        buf.drain(0..drop_n);
    }
}

/// Parse the `ROOMLERD_LOGS_UPLOAD_DISABLED` env-var. Accepts
/// `1`, `true`, `yes`, `on` (case-insensitive, trimmed) as truthy;
/// anything else (including `None`) is false — i.e. uploads stay ON
/// per the rc.58 default-on policy.
pub fn parse_disable_flag(value: Option<&str>) -> bool {
    match value {
        Some(v) => matches!(
            v.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        None => false,
    }
}

/// SHA256-hash the hostname (lowercased, trimmed). Hex-encoded; 64
/// chars. Used as the `host_id_hash` field on uploaded batches so the
/// admin UI can group lines by host without revealing the raw name.
/// Mirrors the rule established in `ed69c6c` (PII scrub): code never
/// holds the raw hostname; telemetry doesn't either.
pub fn hash_hostname(name: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(name.trim().to_ascii_lowercase().as_bytes());
    let out = hasher.finalize();
    hex::encode(out)
}

#[allow(dead_code)]
fn _arc_assert_send_sync<T: Send + Sync>(_: Arc<T>) {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_disable_flag_accepts_truthy() {
        assert!(parse_disable_flag(Some("1")));
        assert!(parse_disable_flag(Some("true")));
        assert!(parse_disable_flag(Some("True")));
        assert!(parse_disable_flag(Some("yes")));
        assert!(parse_disable_flag(Some("on")));
        assert!(parse_disable_flag(Some("  ON  ")));
    }

    #[test]
    fn parse_disable_flag_rejects_falsy() {
        assert!(!parse_disable_flag(None));
        assert!(!parse_disable_flag(Some("")));
        assert!(!parse_disable_flag(Some("0")));
        assert!(!parse_disable_flag(Some("false")));
        assert!(!parse_disable_flag(Some("no")));
        assert!(!parse_disable_flag(Some("off")));
        assert!(!parse_disable_flag(Some("disabled")));
    }

    #[test]
    fn hash_hostname_is_stable() {
        // Same input → same hash; trim + lowercase normalisation.
        assert_eq!(hash_hostname("WINHOST-A"), hash_hostname("winhost-a"));
        assert_eq!(hash_hostname("WINHOST-A"), hash_hostname("  WINHOST-A  "));
        assert_ne!(hash_hostname("WINHOST-A"), hash_hostname("WINHOST-D"));
        // Output length is the SHA256 hex (64 chars).
        assert_eq!(hash_hostname("WINHOST-A").len(), 64);
    }

    #[test]
    fn strip_outer_quotes_handles_short_strings() {
        assert_eq!(strip_outer_quotes(""), "");
        assert_eq!(strip_outer_quotes("\""), "\"");
        assert_eq!(strip_outer_quotes("\"\""), "");
        assert_eq!(strip_outer_quotes("\"abc\""), "abc");
        assert_eq!(strip_outer_quotes("abc"), "abc");
    }

    /// Smoke test: layer constructor returns a working channel.
    #[tokio::test]
    async fn layer_construction_round_trip() {
        let (_layer, mut rx) = LogUploadLayer::new();
        // Nothing should be in the channel yet.
        assert!(matches!(
            rx.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    }

    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::Duration;

    /// The production pace scaled down 100×: flush every 50 ms, back off
    /// from 50 ms up to 600 ms.
    const FAST: Pace = Pace {
        flush: Duration::from_millis(50),
        initial_backoff: Duration::from_millis(50),
        max_backoff: Duration::from_millis(600),
    };

    /// A loopback HTTP server that reads each whole request, counts it, and
    /// answers `status` with an empty body. Returns its base URL and the count.
    async fn counting_server(status: &'static str) -> (String, Arc<AtomicUsize>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let base = format!("http://{}", listener.local_addr().unwrap());
        let posts = Arc::new(AtomicUsize::new(0));
        let seen = posts.clone();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = listener.accept().await {
                let seen = seen.clone();
                tokio::spawn(async move {
                    let mut req: Vec<u8> = Vec::new();
                    let mut chunk = [0u8; 8192];
                    let mut want: Option<usize> = None;
                    loop {
                        if let Some(total) = want
                            && req.len() >= total
                        {
                            break;
                        }
                        let n = s.read(&mut chunk).await.unwrap_or(0);
                        if n == 0 {
                            return;
                        }
                        req.extend_from_slice(&chunk[..n]);
                        if want.is_none()
                            && let Some(end) = req.windows(4).position(|w| w == b"\r\n\r\n")
                        {
                            let head = String::from_utf8_lossy(&req[..end]).to_ascii_lowercase();
                            let len = head
                                .lines()
                                .find_map(|l| l.strip_prefix("content-length:"))
                                .and_then(|v| v.trim().parse::<usize>().ok())
                                .unwrap_or(0);
                            want = Some(end + 4 + len);
                        }
                    }
                    seen.fetch_add(1, Ordering::SeqCst);
                    let reply = format!(
                        "HTTP/1.1 {status}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    );
                    let _ = s.write_all(reply.as_bytes()).await;
                });
            }
        });
        (base, posts)
    }

    fn config(base: &str, token: &crate::token_slot::TokenSlot) -> UploadConfig {
        UploadConfig {
            server_url: base.to_string(),
            tenant_id: "t1".into(),
            agent_id: "a1".into(),
            agent_jwt: token.clone(),
            agent_version: "0.0.0-test".into(),
            host_id_hash: hash_hostname("host"),
            source: LogSource::Agent,
        }
    }

    /// Feed one line every 10 ms until the channel closes, as a busy daemon's
    /// log does, so every flush finds a batch.
    fn feed(tx: mpsc::Sender<LogLine>) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            loop {
                let line = LogLine {
                    ts: DateTime::now(),
                    level: LogLevel::Warn,
                    target: "test".into(),
                    msg: "overlay derp: /derp connect failed".into(),
                    fields: Document::new(),
                };
                if tx.send(line).await.is_err() {
                    return;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
    }

    /// #2512 — a 401 waits out the long backoff, as the module doc says.
    /// Before, the arm set the backoff and went straight back to the flush
    /// tick: one POST per flush, forever (88 in 13 minutes in the field).
    #[tokio::test]
    async fn a_401_waits_the_long_backoff_out() {
        let (base, posts) = counting_server("401 Unauthorized").await;
        let token = crate::token_slot::TokenSlot::new("gone");
        let (tx, rx) = mpsc::channel(CHANNEL_CAPACITY);
        let feeder = feed(tx);
        let uploader = tokio::spawn(run_uploader_paced(rx, config(&base, &token), FAST));
        tokio::time::sleep(Duration::from_millis(1500)).await;
        uploader.abort();
        feeder.abort();
        let n = posts.load(Ordering::SeqCst);
        // At ~50 ms, ~650 ms and ~1250 ms, where the flush tick alone made ~30.
        assert!((1..=4).contains(&n), "{n} POSTs in 1.5 s against a 401");
    }

    /// #2512 — while the control socket's verdict on the token is "refused",
    /// nothing is posted at all. A renewed token resumes the uploads.
    #[tokio::test]
    async fn a_refused_token_posts_nothing_until_it_changes() {
        let (base, posts) = counting_server("204 No Content").await;
        let token = crate::token_slot::TokenSlot::new("gone");
        assert!(token.mark_refused("gone"));
        let (tx, rx) = mpsc::channel(CHANNEL_CAPACITY);
        let feeder = feed(tx);
        let uploader = tokio::spawn(run_uploader_paced(rx, config(&base, &token), FAST));
        tokio::time::sleep(Duration::from_millis(600)).await;
        assert_eq!(
            posts.load(Ordering::SeqCst),
            0,
            "a refused token posts nothing"
        );
        assert!(token.set("renewed".into()));
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while posts.load(Ordering::SeqCst) == 0 {
            assert!(
                std::time::Instant::now() < deadline,
                "a renewed token's uploads resume on the next flush"
            );
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        uploader.abort();
        feeder.abort();
    }
}
