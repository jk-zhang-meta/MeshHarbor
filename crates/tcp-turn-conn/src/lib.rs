// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! TURNS-over-TLS-over-TCP `Conn` adapter for relay candidate gathering.
//!
//! P5 (consolidation invariant I5) — this crate IS the substance of the
//! `webrtc-ice` fork, extracted verbatim so the vendored tree shrinks to a
//! mechanical ~40-line patch (gather match-arm + dep line) auditable against
//! pristine upstream (`crates/vendored/webrtc-ice.patch` +
//! `scripts/revendor-webrtc-ice.sh`). Consumed by BOTH the vendored
//! `webrtc-ice`'s gather path (the agent's WebRTC remote-desktop relay) and
//! `tunnel-core`'s overlay TURN allocator — which therefore no longer
//! depends on the fork at all.
//!
//! # Why this exists
//!
//! Upstream `webrtc-ice::agent::agent_gather::gather_candidates_relay`
//! implements ONE relay-transport branch: TURN over UDP. TURN/TCP,
//! TURNS/TCP and TURNS/UDP (DTLS) all fall through to a `log::warn!`
//! ("Unable to handle URL") and return without creating a candidate.
//! Upstream tracking: <https://github.com/webrtc-rs/webrtc/issues/690>
//! — closed 2026-01-31 as **NOT_PLANNED**.
//!
//! For our `roomlerd` deployed on corporate Windows endpoints
//! that block ALL outbound UDP but allow outbound TCP/443, the only
//! viable relay path is TURNS-over-TLS-over-TCP. This module adapts
//! a `tokio_rustls::client::TlsStream<TcpStream>` into the
//! `util::Conn` trait the `turn::client::Client` consumes, so the
//! existing crate's relay machinery can drive it unmodified.
//!
//! # Framing
//!
//! The `turn::client::Client::listen()` loop calls `conn.recv_from()`
//! once per TURN frame. On UDP each datagram is naturally one frame.
//! On TCP we get a byte stream that may contain multiple frames per
//! `tokio::io::AsyncRead::read()` call, or a single frame split across
//! several reads. The adapter buffers and yields exactly one frame
//! per `recv_from()` call.
//!
//! Frame layouts:
//!
//! * **STUN message** ([RFC 5389 §6](https://www.rfc-editor.org/rfc/rfc5389#section-6)):
//!   `[type:2 | length:2 | magic_cookie:4 | txn_id:12 | attributes]`.
//!   The `length` field counts only the attributes (padded internally
//!   to 4-byte boundaries — already inside `length`). Total frame
//!   bytes = `20 + length`.
//!
//! * **ChannelData** ([RFC 5766 §11.4](https://www.rfc-editor.org/rfc/rfc5766#section-11.4)
//!   and [§11.5](https://www.rfc-editor.org/rfc/rfc5766#section-11.5)):
//!   `[channel_no:2 | length:2 | data:length]`. RFC 5766 §11.5
//!   requires 4-byte boundary alignment of the **entire frame** when
//!   the transport is TCP (so receivers can frame the stream), so we
//!   round the total up to the next multiple of 4. The `turn-0.9.0`
//!   crate's `ChannelData::encode()` always pads on send, regardless
//!   of transport, so coturn over TCP definitely sends padded frames.
//!
//! Discriminator: first 2 bits of byte 0.
//! * `0b00xxxxxx` → STUN message (type field's class bits are 00).
//! * `0b01xxxxxx` → ChannelData (channel numbers live in `[0x4000,0x7FFE]`).
//! * `0b10xxxxxx` / `0b11xxxxxx` → malformed; we disconnect.

use std::any::Any;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::sync::OnceLock;

use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt, ReadHalf, WriteHalf};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_rustls::client::TlsStream;
use tokio_rustls::TlsConnector;
use util::{Conn, Error};

/// Initial read-buffer capacity. 4 KiB covers most STUN messages
/// (typical ~100 bytes) and ChannelData up to ~3.5 KiB without
/// reallocating.
const INITIAL_RX_CAPACITY: usize = 4096;

/// Hard cap on a single TURN frame. STUN/TURN messages declare a
/// 16-bit length so the protocol max is ~65 KiB; we use 70 KiB as a
/// defensive cap to also cover the `+4` ChannelData header without
/// arithmetic in the bounds check.
const MAX_FRAME_BYTES: usize = 70_000;

/// One TURN frame parsed off a TLS-over-TCP byte stream.
///
/// Returns `Ok(Some(total_bytes))` when `buf` contains at least one
/// header (4 bytes) AND those bytes describe a valid frame layout.
/// `total_bytes` is the size of the WHOLE frame including the header
/// and any RFC 5766 §11.5 trailing-pad bytes; the caller is expected
/// to consume exactly that many bytes when the full frame is in the
/// buffer.
///
/// Returns `Ok(None)` when `buf` is too short to determine the size
/// (fewer than 4 bytes).
///
/// Returns `Err` when the leading bits do not match either STUN or
/// ChannelData: this is unrecoverable on a byte stream (we have no
/// way to resynchronise without a framing layer), so the caller MUST
/// disconnect.
pub(crate) fn parse_frame_len(buf: &[u8]) -> Result<Option<usize>, &'static str> {
    if buf.len() < 4 {
        return Ok(None);
    }
    // STUN message types start with class bits 00 (RFC 5389 §6).
    // ChannelData numbers start with bits 01 (RFC 5766 §11.4, channels
    // in [0x4000, 0x7FFE]). Top two bits 10 and 11 are reserved.
    let class = buf[0] & 0xC0;
    let len_field = u16::from_be_bytes([buf[2], buf[3]]) as usize;
    match class {
        0x00 => Ok(Some(20 + len_field)),
        0x40 => {
            let body = 4 + len_field;
            // Round up to next multiple of 4 (RFC 5766 §11.5 — TCP frame
            // boundaries are aligned to 4 bytes by the sender so the
            // receiver can re-frame the stream). turn-0.9.0 always pads
            // on encode; coturn does the same.
            Ok(Some((body + 3) & !3))
        }
        _ => Err("malformed TURN frame header — top two bits are reserved"),
    }
}

/// `Conn`-trait adapter wrapping a TLS-over-TCP connection to a TURN
/// server. The relay client (`turn::client::Client`) holds an
/// `Arc<dyn Conn>` and calls `recv_from`/`send_to` against it; this
/// adapter de-frames the inbound byte stream into one STUN or
/// ChannelData message per `recv_from` call and passes outbound
/// bytes through unchanged.
pub struct TcpTurnConn {
    read: Mutex<ReadState>,
    write: Mutex<WriteHalf<TlsStream<TcpStream>>>,
    local: SocketAddr,
    remote: SocketAddr,
    closed: AtomicBool,
}

struct ReadState {
    half: ReadHalf<TlsStream<TcpStream>>,
    /// Bytes already pulled from TCP but not yet returned as a frame.
    /// Holds at most one partial frame plus tail bytes of the next.
    rx_buf: Vec<u8>,
}

impl TcpTurnConn {
    /// Connect a fresh TCP stream + drive the TLS handshake, then
    /// wrap the result for use by `turn::client::Client`.
    ///
    /// `hostname` is used for SNI + server certificate verification.
    /// For an enrollment URL `turns:coturn.roomler.ai:443?transport=tcp`,
    /// pass `"coturn.roomler.ai"`.
    pub async fn connect_tls(tcp: TcpStream, hostname: &str) -> Result<Self, std::io::Error> {
        let local = tcp.local_addr()?;
        let remote = tcp.peer_addr()?;
        // Disable Nagle so STUN keepalives ship immediately. The TURN
        // control channel sends very small messages and conntrack on
        // the server side keys off arrival, not coalesced batches.
        tcp.set_nodelay(true)?;
        let server_name = tokio_rustls::rustls::pki_types::ServerName::try_from(
            hostname.to_string(),
        )
        .map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid SNI name: {hostname}"),
            )
        })?;
        let connector = TlsConnector::from(tls_client_config());
        let tls = connector.connect(server_name, tcp).await?;
        let (rd, wr) = tokio::io::split(tls);
        Ok(Self {
            read: Mutex::new(ReadState {
                half: rd,
                rx_buf: Vec::with_capacity(INITIAL_RX_CAPACITY),
            }),
            write: Mutex::new(wr),
            local,
            remote,
            closed: AtomicBool::new(false),
        })
    }
}

#[async_trait]
impl Conn for TcpTurnConn {
    async fn connect(&self, _addr: SocketAddr) -> Result<(), Error> {
        // We're already connected via `connect_tls`. `turn::client`
        // never calls this — provided for `Conn` trait completeness.
        Ok(())
    }

    async fn recv(&self, buf: &mut [u8]) -> Result<usize, Error> {
        let (n, _) = self.recv_from(buf).await?;
        Ok(n)
    }

    async fn recv_from(&self, out: &mut [u8]) -> Result<(usize, SocketAddr), Error> {
        let mut state = self.read.lock().await;
        loop {
            if self.closed.load(Ordering::Relaxed) {
                return Err(Error::Other("tcp-turn conn closed".to_string()));
            }
            // Try to extract one complete frame.
            match parse_frame_len(&state.rx_buf) {
                Ok(Some(total)) => {
                    if total > MAX_FRAME_BYTES {
                        return Err(Error::Other(format!(
                            "TURN frame too large ({total} bytes) — disconnecting"
                        )));
                    }
                    if total > out.len() {
                        return Err(Error::ErrBufferShort);
                    }
                    if state.rx_buf.len() >= total {
                        out[..total].copy_from_slice(&state.rx_buf[..total]);
                        // Drain the consumed bytes; rotate the tail to the front.
                        state.rx_buf.drain(..total);
                        return Ok((total, self.remote));
                    }
                    // Fall through to read more.
                }
                Ok(None) => {
                    // Need at least 4 bytes to peek the length field.
                }
                Err(reason) => {
                    return Err(Error::Other(format!(
                        "tcp-turn framing error: {reason} \
                         (first 4 bytes: {:02X?})",
                        &state.rx_buf[..state.rx_buf.len().min(4)]
                    )));
                }
            }
            // Append more bytes from the wire.
            let mut chunk = [0u8; 4096];
            let n = state
                .half
                .read(&mut chunk)
                .await
                .map_err(|e| Error::Other(format!("tcp-turn read: {e}")))?;
            if n == 0 {
                self.closed.store(true, Ordering::Relaxed);
                return Err(Error::Other("tcp-turn peer closed connection".to_string()));
            }
            state.rx_buf.extend_from_slice(&chunk[..n]);
        }
    }

    async fn send(&self, buf: &[u8]) -> Result<usize, Error> {
        self.send_to(buf, self.remote).await
    }

    async fn send_to(&self, data: &[u8], _target: SocketAddr) -> Result<usize, Error> {
        if self.closed.load(Ordering::Relaxed) {
            return Err(Error::Other("tcp-turn conn closed".to_string()));
        }
        let mut wr = self.write.lock().await;
        wr.write_all(data)
            .await
            .map_err(|e| Error::Other(format!("tcp-turn write: {e}")))?;
        wr.flush()
            .await
            .map_err(|e| Error::Other(format!("tcp-turn flush: {e}")))?;
        Ok(data.len())
    }

    fn local_addr(&self) -> Result<SocketAddr, Error> {
        Ok(self.local)
    }

    fn remote_addr(&self) -> Option<SocketAddr> {
        Some(self.remote)
    }

    async fn close(&self) -> Result<(), Error> {
        self.closed.store(true, Ordering::Relaxed);
        let mut wr = self.write.lock().await;
        let _ = wr.shutdown().await; // Best-effort.
        Ok(())
    }

    fn as_any(&self) -> &(dyn Any + Send + Sync) {
        self
    }
}

/// Lazily-built shared `tokio_rustls::rustls::ClientConfig`. Created
/// on first call; subsequent connections reuse the same `Arc`.
///
/// Trust-store strategy: load the **OS-native** cert store first, then
/// extend with Mozilla's `webpki-roots` bundle. The native step is
/// load-bearing on corporate Windows endpoints — IT pushes a private
/// CA into the Windows cert store so all outbound HTTPS gets
/// intercepted by their TLS-inspection proxy. Browsers + `reqwest`
/// (Schannel) trust those private CAs because they read the native
/// store; the prior `webpki-roots`-only build failed with
/// `UnknownIssuer` on a third field-test host because the proxy's cert was signed by
/// a corporate CA Mozilla doesn't ship. Loading both stores makes the
/// agent resilient on TLS-intercepted networks AND keeps working on
/// direct-internet hosts where the native store may be sparse.
fn tls_client_config() -> Arc<tokio_rustls::rustls::ClientConfig> {
    static CONFIG: OnceLock<Arc<tokio_rustls::rustls::ClientConfig>> = OnceLock::new();
    CONFIG
        .get_or_init(|| {
            let mut root = tokio_rustls::rustls::RootCertStore::empty();

            // (1) Native OS cert store. Failures here are non-fatal —
            // on locked-down systems where the store API errors out,
            // we still have Mozilla's bundle below.
            let native = rustls_native_certs::load_native_certs();
            if !native.certs.is_empty() {
                let (added, _ignored) = root.add_parsable_certificates(native.certs);
                // info! (not debug!) so the count is visible in field logs
                // without needing RUST_LOG=debug. Helps confirm that the
                // OS-native store actually contributed CAs when troubleshooting
                // TLS-inspection scenarios on corporate networks.
                log::info!(
                    "tcp-turn TLS: loaded {} native cert(s) (errors: {})",
                    added,
                    native.errors.len()
                );
            } else {
                log::warn!(
                    "tcp-turn TLS: native cert store returned no certs \
                     (errors: {}) — falling through to webpki-roots only",
                    native.errors.len()
                );
            }

            // (2) Mozilla bundle — keeps direct-internet hosts working
            // when the native store is sparse (e.g. Linux without
            // ca-certificates installed).
            root.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

            let cfg = tokio_rustls::rustls::ClientConfig::builder()
                .with_root_certificates(root)
                .with_no_client_auth();
            Arc::new(cfg)
        })
        .clone()
}

#[cfg(test)]
mod tests {
    use super::parse_frame_len;

    // ─────────────────────────────────────────────────────────────────────
    // Synthetic STUN / ChannelData byte sequences
    // ─────────────────────────────────────────────────────────────────────

    /// Build the first 4 bytes of a STUN Binding Request with the given
    /// attributes-length. Bytes 4..20 (magic cookie + txn ID) are filler.
    fn stun_header(attributes_len: u16) -> Vec<u8> {
        // STUN type 0x0001 (Binding Request, class=00 indicator bits are 00).
        let mut hdr = vec![0x00, 0x01];
        hdr.extend_from_slice(&attributes_len.to_be_bytes());
        // Magic cookie 0x2112A442 + 12-byte txn ID — pad with zero so the
        // header length is the full 20 bytes that parse_frame_len adds to
        // the attributes_len.
        hdr.extend_from_slice(&[0x21, 0x12, 0xA4, 0x42]);
        hdr.extend_from_slice(&[0u8; 12]);
        hdr
    }

    /// Build a ChannelData header for channel 0x4000 + given data length.
    /// Pads the body to a 4-byte boundary per RFC 5766 §11.5 (TCP).
    fn chandata_frame(channel: u16, data_len: u16) -> Vec<u8> {
        assert!(channel & 0xC000 == 0x4000, "channel num must start with 01");
        let mut frame = Vec::new();
        frame.extend_from_slice(&channel.to_be_bytes());
        frame.extend_from_slice(&data_len.to_be_bytes());
        frame.extend(std::iter::repeat_n(0xCC, data_len as usize));
        while frame.len() % 4 != 0 {
            frame.push(0x00);
        }
        frame
    }

    // ─────────────────────────────────────────────────────────────────────
    // parse_frame_len: STUN
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn stun_zero_attributes_is_20_bytes() {
        let hdr = stun_header(0);
        assert_eq!(parse_frame_len(&hdr).unwrap(), Some(20));
    }

    #[test]
    fn stun_with_attributes_includes_length_field() {
        let hdr = stun_header(48);
        assert_eq!(parse_frame_len(&hdr).unwrap(), Some(20 + 48));
    }

    #[test]
    fn stun_max_length_is_handled() {
        let hdr = stun_header(0xFFFF);
        assert_eq!(parse_frame_len(&hdr).unwrap(), Some(20 + 0xFFFF));
    }

    // ─────────────────────────────────────────────────────────────────────
    // parse_frame_len: ChannelData
    //
    // CRITICAL — this is the R1 fix from the plan critique. ChannelData
    // over TCP MUST be 4-byte aligned (RFC 5766 §11.5). The framer is
    // responsible for consuming the pad bytes; missing them causes the
    // next frame parse to read the pad bytes as a malformed header.
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn chandata_no_padding_when_length_is_aligned() {
        // Channel 0x4000, 4 bytes data → total = 4 + 4 = 8 (already aligned).
        let frame = chandata_frame(0x4000, 4);
        assert_eq!(frame.len(), 8);
        assert_eq!(parse_frame_len(&frame).unwrap(), Some(8));
    }

    #[test]
    fn chandata_pads_to_next_4byte_boundary() {
        // 1 byte data → 4+1=5, rounded up to 8.
        let frame = chandata_frame(0x4000, 1);
        assert_eq!(frame.len(), 8);
        assert_eq!(parse_frame_len(&frame).unwrap(), Some(8));

        // 2 bytes → 4+2=6 → 8.
        let frame = chandata_frame(0x4000, 2);
        assert_eq!(frame.len(), 8);
        assert_eq!(parse_frame_len(&frame).unwrap(), Some(8));

        // 3 bytes → 4+3=7 → 8.
        let frame = chandata_frame(0x4000, 3);
        assert_eq!(frame.len(), 8);
        assert_eq!(parse_frame_len(&frame).unwrap(), Some(8));

        // 5 bytes → 4+5=9 → 12.
        let frame = chandata_frame(0x4000, 5);
        assert_eq!(frame.len(), 12);
        assert_eq!(parse_frame_len(&frame).unwrap(), Some(12));

        // 1450 bytes (typical MTU-ish RTP) → 4+1450=1454 → 1456.
        let frame = chandata_frame(0x4000, 1450);
        assert_eq!(frame.len(), 1456);
        assert_eq!(parse_frame_len(&frame).unwrap(), Some(1456));
    }

    #[test]
    fn chandata_max_channel_number_is_valid() {
        // 0x7FFE is the last valid channel per RFC 5766. The first 2 bits
        // must be 01, so anything 0x4000..=0x7FFF passes the class check.
        let frame = chandata_frame(0x7FFE, 100);
        assert!(parse_frame_len(&frame).is_ok());
    }

    // ─────────────────────────────────────────────────────────────────────
    // parse_frame_len: incomplete + malformed
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn incomplete_header_returns_none() {
        for buf in [
            &[][..],
            &[0x00][..],
            &[0x00, 0x01][..],
            &[0x00, 0x01, 0x00][..],
        ] {
            assert_eq!(parse_frame_len(buf).unwrap(), None, "buf={buf:?}");
        }
    }

    #[test]
    fn malformed_top_bits_rejected() {
        // Top 2 bits 10 — reserved.
        let bad = vec![0x80, 0x00, 0x00, 0x00];
        assert!(parse_frame_len(&bad).is_err(), "0x80... must reject");
        // Top 2 bits 11 — reserved.
        let bad = vec![0xC0, 0x00, 0x00, 0x00];
        assert!(parse_frame_len(&bad).is_err(), "0xC0... must reject");
        let bad = vec![0xFF, 0xFF, 0x00, 0x00];
        assert!(parse_frame_len(&bad).is_err(), "0xFF... must reject");
    }

    // ─────────────────────────────────────────────────────────────────────
    // Realistic sequences — multiple frames concatenated
    //
    // These don't exercise parse_frame_len directly but verify the
    // invariant the recv_from() loop depends on: after consuming a frame's
    // declared length, the next byte starts a new well-formed frame.
    // ─────────────────────────────────────────────────────────────────────

    #[test]
    fn back_to_back_chandata_frames_align_correctly() {
        // Two frames: 5 bytes data (→ 12-byte frame with 3 pad), then
        // 4 bytes data (→ 8-byte frame, no pad). Concatenated.
        let mut stream = chandata_frame(0x4000, 5);
        stream.extend_from_slice(&chandata_frame(0x4001, 4));

        let first_len = parse_frame_len(&stream).unwrap().unwrap();
        assert_eq!(first_len, 12);
        let next = &stream[first_len..];
        let second_len = parse_frame_len(next).unwrap().unwrap();
        assert_eq!(second_len, 8);
        assert_eq!(next.len(), 8);
    }

    #[test]
    fn stun_followed_by_chandata_aligns_correctly() {
        // STUN (Binding Request, no attributes → 20 bytes) followed by
        // ChannelData(5 bytes → 12 bytes). The "+3 to 4" rounding on the
        // ChannelData side must not bleed into the STUN parse.
        let mut stream = stun_header(0);
        stream.extend_from_slice(&chandata_frame(0x4000, 5));

        let first = parse_frame_len(&stream).unwrap().unwrap();
        assert_eq!(first, 20);
        let next = &stream[first..];
        let second = parse_frame_len(next).unwrap().unwrap();
        assert_eq!(second, 12);
        assert_eq!(next.len(), 12);
    }

    /// Actual TLS sockets, not only frame-length arithmetic. Linux test child
    /// gets an ephemeral trust file via its own environment before OnceLock;
    /// no process-global env mutation, OS trust edit, or verifier bypass.
    #[cfg(target_os = "linux")]
    #[test]
    fn real_tls_stream_fragment_coalesce_eof_and_hostname() {
        use std::os::unix::fs::DirBuilderExt;
        use std::path::PathBuf;
        use std::process::{Command, Stdio};
        use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
        const CHILD: &str = "TCP_TURN_TLS_TEST_CHILD_DIR";
        if let Some(path) = std::env::var_os(CHILD) {
            let dir = PathBuf::from(path);
            assert!(dir.is_dir() && !dir.is_symlink());
            assert_eq!(
                std::env::var_os("SSL_CERT_FILE"),
                Some(dir.join("ca.pem").into_os_string())
            );
            assert!(std::env::var_os("SSL_CERT_DIR").is_none());
            // libtest --nocapture may leave its "test ... " prefix on this
            // line. Keep every exact marker on an independent line.
            println!();
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async {
                tokio::time::timeout(Duration::from_secs(15), real_tls_stream_child(&dir))
                    .await
                    .expect("15s TLS child deadline")
                    .expect("real TLS stream oracle")
            });
            return;
        }
        let dir = std::env::temp_dir().join(format!(
            "meshharbor-tcp-turn-tls-test-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::DirBuilder::new().mode(0o700).create(&dir).unwrap();
        struct Cleanup(PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                // Only this invocation's known public test certificate/path.
                let _ = std::fs::remove_file(self.0.join("ca.pem"));
                let _ = std::fs::remove_dir(&self.0);
            }
        }
        let cleanup = Cleanup(dir.clone());
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "tests::real_tls_stream_fragment_coalesce_eof_and_hostname",
                "--nocapture",
                "--test-threads=1",
            ])
            .env(CHILD, &dir)
            .env("SSL_CERT_FILE", dir.join("ca.pem"))
            .env_remove("SSL_CERT_DIR")
            .env("RUST_LOG", "off")
            .env("RUST_BACKTRACE", "0")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let began = Instant::now();
        loop {
            if child.try_wait().unwrap().is_some() {
                break;
            }
            if began.elapsed() >= Duration::from_secs(25) {
                let _ = child.kill();
                let _ = child.wait();
                panic!("25s parent deadline killed owned TLS test child");
            }
            std::thread::sleep(Duration::from_millis(25));
        }
        let output = child.wait_with_output().unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success(),
            "TLS child status={} stderr={}",
            output.status,
            String::from_utf8_lossy(&output.stderr)
                .chars()
                .take(4096)
                .collect::<String>()
        );
        for marker in [
            "TCP_TURN_TLS_HANDSHAKE_PASS",
            "TCP_TURN_TLS_FRAGMENT_COALESCE_PASS",
            "TCP_TURN_TLS_SEND_FRAME_PASS",
            "TCP_TURN_TLS_PARTIAL_EOF_PASS",
            "TCP_TURN_TLS_WRONG_HOSTNAME_REJECTED",
        ] {
            assert_eq!(
                stdout.lines().filter(|line| *line == marker).count(),
                1,
                "missing/duplicate TLS oracle marker {marker}"
            );
            println!("{marker}");
        }
        drop(cleanup);
        assert!(!dir.exists(), "task TLS certificate directory not removed");
    }

    #[cfg(target_os = "linux")]
    async fn real_tls_stream_child(
        dir: &std::path::Path,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        use std::sync::Arc;
        use std::time::Duration;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::{TcpListener, TcpStream};
        use tokio::sync::oneshot;
        use tokio_rustls::rustls::{
            pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer},
            ServerConfig,
        };
        use tokio_rustls::TlsAcceptor;
        use util::Conn;

        let rcgen::CertifiedKey { cert, key_pair } =
            rcgen::generate_simple_self_signed(vec!["localhost".to_owned()])?;
        let mut ca = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(dir.join("ca.pem"))?;
        ca.write_all(cert.pem().as_bytes())?;
        drop(ca); // Certificate is public; ephemeral private key stays in memory.
        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![cert.der().clone()],
                PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der())),
            )?;
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
        let addr = listener.local_addr()?;
        let frames = [
            stun_header(0),
            chandata_frame(0x4000, 5),
            chandata_frame(0x4001, 4),
        ];
        let expected = frames.clone();
        let request = stun_header(0);
        let request_for_server = request.clone();
        let (fragment_tx, fragment_rx) = oneshot::channel();
        let (release_tx, release_rx) = oneshot::channel();
        let server_acceptor = acceptor.clone();
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await?;
            let mut tls = server_acceptor.accept(tcp).await?;
            tls.write_all(&frames[0][..2]).await?;
            tls.flush().await?;
            let _ = fragment_tx.send(());
            release_rx.await?;
            // Remainder of a fragmented STUN frame PLUS two ChannelData
            // frames in one TLS write: read boundaries cannot be assumed.
            let mut joined = frames[0][2..].to_vec();
            joined.extend_from_slice(&frames[1]);
            joined.extend_from_slice(&frames[2]);
            tls.write_all(&joined).await?;
            tls.flush().await?;
            let mut received = vec![0; request_for_server.len()];
            tls.read_exact(&mut received).await?;
            assert_eq!(
                received, request_for_server,
                "TLS adapter outbound frame changed"
            );
            // Declare 28 bytes but send only six before close-notify/EOF.
            // recv_from must error, not return a truncated TURN frame or hang.
            tls.write_all(&[0x00, 0x01, 0x00, 0x08, 0x21, 0x12]).await?;
            tls.shutdown().await?;
            Ok::<(), Box<dyn std::error::Error + Send + Sync>>(())
        });
        let tcp = TcpStream::connect(addr).await?;
        let client = super::TcpTurnConn::connect_tls(tcp, "localhost").await?;
        println!("TCP_TURN_TLS_HANDSHAKE_PASS");
        fragment_rx.await?;
        let mut buf = [0u8; 512];
        assert!(
            tokio::time::timeout(Duration::from_millis(30), client.recv_from(&mut buf))
                .await
                .is_err(),
            "two-byte TLS fragment must not produce a TURN frame"
        );
        let _ = release_tx.send(());
        for frame in expected {
            let (n, peer) =
                tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buf)).await??;
            assert_eq!(peer, addr);
            assert_eq!(n, frame.len());
            assert_eq!(&buf[..n], frame.as_slice());
        }
        println!("TCP_TURN_TLS_FRAGMENT_COALESCE_PASS");
        assert_eq!(client.send_to(&request, addr).await?, request.len());
        tokio::time::timeout(Duration::from_secs(2), server).await???;
        println!("TCP_TURN_TLS_SEND_FRAME_PASS");
        assert!(
            tokio::time::timeout(Duration::from_secs(2), client.recv_from(&mut buf))
                .await?
                .is_err(),
            "partial TLS frame EOF must fail"
        );
        client.close().await?;
        assert!(
            client.send(&request).await.is_err(),
            "closed TLS adapter accepted a send"
        );
        println!("TCP_TURN_TLS_PARTIAL_EOF_PASS");

        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
        let addr = listener.local_addr()?;
        let server = tokio::spawn(async move {
            let (tcp, _) = listener.accept().await?;
            let _ = acceptor.accept(tcp).await; // Expected peer certificate alert.
            Ok::<(), std::io::Error>(())
        });
        let tcp = TcpStream::connect(addr).await?;
        let error = match super::TcpTurnConn::connect_tls(tcp, "wrong-hostname.invalid").await {
            Ok(_) => panic!("TLS adapter accepted certificate for the wrong hostname"),
            Err(error) => error.to_string().to_lowercase(),
        };
        assert!(
            error.contains("notvalidforname") || error.contains("not valid for name"),
            "wrong-hostname failure was not certificate-name validation"
        );
        tokio::time::timeout(Duration::from_secs(2), server).await???;
        println!("TCP_TURN_TLS_WRONG_HOSTNAME_REJECTED");
        Ok(())
    }
}
