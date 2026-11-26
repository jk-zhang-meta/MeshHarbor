// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-141 — Built-in resumable `russh` + `crossterm` SSH client for `mh ssh`.
//!
//! Owns the local terminal, keeps a client-side shadow `VtScreenTracker`, paints
//! a non-corrupting top-row recovery overlay while disconnected, buffers c2s
//! keystrokes up to 64 KiB for exact-once delivery, reconnects transparently
//! across Wi-Fi/VPN drops and target daemon self-updates, and falls back to
//! classic `pty-req + shell` on the SAME authenticated connection when talking
//! to older targets (< 0.4.219).

use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use crossterm::terminal;
use meshharbor_node_core::pty_resume::{
    MAX_C2S_QUEUE_BYTES, MAX_DATA_CHUNK, NoticeKind, RefuseReason, STREAM_STDIN, STREAM_STDOUT,
    SUBSYSTEM_NAME, SessionMode,
    frame::{AttachFrame, FrameDecoder, OpenFrame, WireFrame},
    now_unix_ms,
    proof::{compute_client_proof, verify_server_proof},
    seq::{C2sClientQueue, VtScreenTracker},
};
use rand::RngCore;
use russh::keys::ssh_key::{PrivateKey, PublicKey};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::sync::mpsc;

use super::escape::{FilterAction, InputFilter};
use super::overlay::{OverlayReason, prefers_zh, render_banner_ansi, restore_title_ansi};
use super::store::{self, StoredSession};

const SSH_USER: &str = "meshharbor";
const PING_EVERY: Duration = Duration::from_secs(2);
const SUSPECT_AFTER: Duration = Duration::from_secs(6);
const HARD_DROP_AFTER: Duration = Duration::from_secs(20);
const OVERLAY_SHOW_DELAY: Duration = Duration::from_secs(1);
const BACKOFF_MS: &[u64] = &[0, 250, 500, 1000, 2000, 4000, 5000];

/// Transport stream accepted by `russh::client::connect_stream` (OS TCP or SOCKS5).
trait OverlayStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> OverlayStream for T {}

struct PinnedHostKey {
    expected: PublicKey,
    mismatch: Arc<AtomicBool>,
}

impl russh::client::Handler for PinnedHostKey {
    type Error = russh::Error;

    async fn check_server_key(&mut self, key: &PublicKey) -> Result<bool, Self::Error> {
        let ok = key.key_data() == self.expected.key_data();
        if !ok {
            self.mismatch.store(true, Ordering::SeqCst);
        }
        Ok(ok)
    }
}

/// RAII terminal raw-mode guard restoring the local TTY on every exit path.
struct RawModeGuard {
    active: bool,
    device: String,
}

impl RawModeGuard {
    fn enter(device: &str) -> Self {
        let active = terminal::enable_raw_mode().is_ok();
        Self {
            active,
            device: device.to_string(),
        }
    }

    fn restore_now(&mut self) {
        if self.active {
            self.active = false;
            let _ = terminal::disable_raw_mode();
            let mut out = std::io::stdout();
            let _ = out.write_all(b"\x1b[?25h\x1b[0m");
            let _ = out.write_all(&restore_title_ansi(&self.device));
            let _ = out.flush();
        }
    }
}

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        self.restore_now();
    }
}

/// Parameters for opening a new resumable SSH session.
pub struct OpenParams {
    pub device: String,
    pub address: String,
    pub port: u16,
    pub socks_port: Option<u16>,
    pub host_pubkey: String,
    pub session_key: PrivateKey,
    pub command: Option<String>,
    pub ephemeral: bool,
}

/// Dial the target over OS-TUN or the local daemon's SOCKS5 netstack front.
async fn dial_target(
    address: &str,
    port: u16,
    socks_port: Option<u16>,
    timeout: Duration,
) -> Result<Box<dyn OverlayStream>> {
    tokio::time::timeout(timeout, async {
        match socks_port {
            Some(socks) => {
                let mut stream =
                    tokio::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, socks))
                        .await
                        .context("connecting to local daemon overlay SOCKS5 front")?;
                tunnel_core::socks5::client_connect(&mut stream, address, port).await?;
                let _ = stream.set_nodelay(true);
                Ok(Box::new(stream) as Box<dyn OverlayStream>)
            }
            None => {
                let stream = tokio::net::TcpStream::connect((address, port))
                    .await
                    .with_context(|| format!("connecting to {address}:{port}"))?;
                let _ = stream.set_nodelay(true);
                Ok(Box::new(stream) as Box<dyn OverlayStream>)
            }
        }
    })
    .await
    .context("connection attempt timed out")?
}

/// Establish an authenticated `russh` session with pinned host-key verification.
async fn connect_and_auth(
    address: &str,
    port: u16,
    socks_port: Option<u16>,
    expected_host_key: &PublicKey,
    session_key: &PrivateKey,
    timeout: Duration,
) -> Result<russh::client::Handle<PinnedHostKey>> {
    let stream = dial_target(address, port, socks_port, timeout).await?;
    let mismatch = Arc::new(AtomicBool::new(false));
    let handler = PinnedHostKey {
        expected: expected_host_key.clone(),
        mismatch: mismatch.clone(),
    };
    let config = Arc::new(russh::client::Config {
        inactivity_timeout: Some(Duration::from_secs(30)),
        ..Default::default()
    });
    let mut handle = match russh::client::connect_stream(config, stream, handler).await {
        Ok(h) => h,
        Err(_) if mismatch.load(Ordering::SeqCst) => {
            bail!("HOST KEY MISMATCH — refusing to connect (pinned key verification failed)")
        }
        Err(e) => return Err(anyhow!("SSH handshake failed: {e}")),
    };

    let hash = handle
        .best_supported_rsa_hash()
        .await
        .ok()
        .flatten()
        .flatten();
    let auth = handle
        .authenticate_publickey(
            SSH_USER,
            russh::keys::PrivateKeyWithHashAlg::new(Arc::new(session_key.clone()), hash),
        )
        .await
        .context("SSH publickey authentication")?;
    if !auth.success() {
        bail!("authentication rejected by target");
    }
    Ok(handle)
}

/// Run a fresh interactive resumable session (with seamless classic fallback on
/// older targets on the exact same authenticated connection!).
pub async fn run_open(params: OpenParams) -> Result<i32> {
    let expected_host_key = PublicKey::from_openssh(params.host_pubkey.trim())
        .context("parsing target SSH host public key")?;
    let host_key_fp = expected_host_key
        .fingerprint(ssh_key::HashAlg::Sha256)
        .to_string();
    let client_key_fp = params
        .session_key
        .public_key()
        .fingerprint(ssh_key::HashAlg::Sha256)
        .to_string();

    let handle = connect_and_auth(
        &params.address,
        params.port,
        params.socks_port,
        &expected_host_key,
        &params.session_key,
        Duration::from_secs(15),
    )
    .await?;

    let (cols, rows) = current_tty_size();
    let term = std::env::var("TERM").unwrap_or_else(|_| "xterm-256color".to_string());
    let env_vars = collect_local_env();

    let mut channel = handle
        .channel_open_session()
        .await
        .context("opening SSH session channel")?;

    // Attempt FR-141 `meshharbor-pty@v1` subsystem first.
    let subsystem_ok = match channel.request_subsystem(true, SUBSYSTEM_NAME).await {
        Ok(()) => wait_subsystem_accepted(&mut channel).await,
        Err(_) => false,
    };

    if !subsystem_ok {
        // Classic fallback on the EXACT SAME authenticated connection — NEVER
        // mint a second grant (single-use key, avoids re-prompting consent/2FA!).
        let zh = prefers_zh();
        let notice = if zh {
            "meshharbor: 目标设备版本暂不支持断线恢复，已回退为经典交互会话（请升级目标 meshharbord 至 0.4.219+）。\r\n"
        } else {
            "meshharbor: target does not support resumable SSH yet; falling back to classic interactive shell (upgrade target to 0.4.219+).\r\n"
        };
        let _ = std::io::stderr().write_all(format!("\x1b[2m{notice}\x1b[0m").as_bytes());
        return run_classic_fallback(handle, &params.device, &term, cols, rows, params.command).await;
    }

    // Read server `Hello`.
    let mut decoder = FrameDecoder::new();
    let _hello = match read_wire_from_channel(&mut channel, &mut decoder, Duration::from_secs(10)).await? {
        Some(WireFrame::Hello(h)) => h,
        other => bail!("unexpected initial frame from target: {other:?}"),
    };

    // Send `Open`.
    send_wire_to_channel(
        &channel,
        &WireFrame::Open(OpenFrame {
            mode: SessionMode::Pty,
            term,
            cols,
            rows,
            command: params.command,
            env: env_vars,
        }),
    )
    .await?;

    // Wait for `Opened` (allows up to 35 s if target prompts operator consent).
    let opened = match read_wire_from_channel(&mut channel, &mut decoder, Duration::from_secs(35)).await? {
        Some(WireFrame::Opened(o)) => o,
        Some(WireFrame::Refused(reason)) => {
            bail!("target refused resumable session: {}", format_refuse(&reason, prefers_zh()));
        }
        other => bail!("unexpected reply to Open: {other:?}"),
    };

    if !opened.persist.survives_restart {
        let zh = prefers_zh();
        let why = opened.persist.reason.as_deref().unwrap_or("unknown");
        let msg = if zh {
            format!("\x1b[2mmeshharbor: 当前会话支持断网恢复，但受环境限制({why})无法跨目标服务重启保留。\x1b[0m\r\n")
        } else {
            format!("\x1b[2mmeshharbor: network resume active; target cannot survive daemon restart ({why}).\x1b[0m\r\n")
        };
        let _ = std::io::stderr().write_all(msg.as_bytes());
    }

    let privkey_openssh = params
        .session_key
        .to_openssh(ssh_key::LineEnding::LF)
        .context("encoding session key")?
        .to_string();

    let stored = StoredSession {
        sid: opened.session_id,
        device: params.device.clone(),
        address: params.address,
        port: params.port,
        socks_port: params.socks_port,
        host_pubkey: params.host_pubkey,
        session_privkey_openssh: privkey_openssh,
        resume_secret_hex: hex::encode(opened.resume_secret),
        created_ms: now_unix_ms(),
        deadline_ms: opened.deadline_ms,
        last_rx: 0,
        c2s_next: 0,
    };
    if !params.ephemeral {
        let _ = store::save(&stored);
    }

    run_interactive_loop(
        stored,
        expected_host_key,
        host_key_fp,
        client_key_fp,
        params.session_key,
        opened.resume_secret,
        params.ephemeral,
        Some((handle, channel, decoder)),
    )
    .await
}

/// Resume a previously detached / crashed-client session from the local store.
pub async fn run_resume(device: &str, prefix: Option<&str>) -> Result<i32> {
    let stored = store::find_by_prefix(device, prefix)?;
    let expected_host_key = PublicKey::from_openssh(stored.host_pubkey.trim())
        .context("parsing stored host public key")?;
    let session_key = PrivateKey::from_openssh(&stored.session_privkey_openssh)
        .context("parsing stored session private key")?;
    let resume_secret = stored.resume_secret()?;
    let host_key_fp = expected_host_key
        .fingerprint(ssh_key::HashAlg::Sha256)
        .to_string();
    let client_key_fp = session_key
        .public_key()
        .fingerprint(ssh_key::HashAlg::Sha256)
        .to_string();

    run_interactive_loop(
        stored,
        expected_host_key,
        host_key_fp,
        client_key_fp,
        session_key,
        resume_secret,
        false,
        None,
    )
    .await
}

/// Terminate a stored remote persistent session (`mh ssh <dev> --kill <id>`).
pub async fn run_kill(device: &str, prefix: &str) -> Result<i32> {
    let stored = store::find_by_prefix(device, Some(prefix))?;
    let expected_host_key = PublicKey::from_openssh(stored.host_pubkey.trim())?;
    let session_key = PrivateKey::from_openssh(&stored.session_privkey_openssh)?;
    let resume_secret = stored.resume_secret()?;
    let host_key_fp = expected_host_key
        .fingerprint(ssh_key::HashAlg::Sha256)
        .to_string();
    let client_key_fp = session_key
        .public_key()
        .fingerprint(ssh_key::HashAlg::Sha256)
        .to_string();

    match dial_and_attach(
        &stored,
        &expected_host_key,
        &session_key,
        &resume_secret,
        &host_key_fp,
        &client_key_fp,
        80,
        24,
    )
    .await
    {
        Ok((handle, channel, _dec, _attached)) => {
            let _ = send_wire_to_channel(&channel, &WireFrame::Terminate).await;
            let _ = handle
                .disconnect(russh::Disconnect::ByApplication, "", "")
                .await;
            store::delete(&stored.sid);
            println!(
                "terminated remote SSH session {} on {}",
                stored.sid.short_hex(),
                stored.device
            );
            Ok(0)
        }
        Err(AttachError::TerminalRefused(RefuseReason::Ended { status })) => {
            store::delete(&stored.sid);
            println!(
                "session {} already exited (code {})",
                stored.sid.short_hex(),
                status.ssh_exit_code()
            );
            Ok(0)
        }
        Err(AttachError::TerminalRefused(reason)) => {
            store::delete(&stored.sid);
            println!(
                "session {} already ended ({})",
                stored.sid.short_hex(),
                format_refuse(&reason, prefers_zh())
            );
            Ok(0)
        }
        Err(AttachError::Transient(e)) => {
            bail!("could not reach {} to terminate session {}: {e}", stored.device, stored.sid.short_hex())
        }
    }
}

enum AttachError {
    Transient(String),
    TerminalRefused(RefuseReason),
}

#[allow(clippy::too_many_arguments)]
async fn dial_and_attach(
    stored: &StoredSession,
    expected_host_key: &PublicKey,
    session_key: &PrivateKey,
    resume_secret: &[u8; 32],
    host_key_fp: &str,
    client_key_fp: &str,
    cols: u16,
    rows: u16,
) -> std::result::Result<
    (
        russh::client::Handle<PinnedHostKey>,
        russh::Channel<russh::client::Msg>,
        FrameDecoder,
        meshharbor_node_core::pty_resume::frame::AttachedFrame,
    ),
    AttachError,
> {
    let handle = connect_and_auth(
        &stored.address,
        stored.port,
        stored.socks_port,
        expected_host_key,
        session_key,
        Duration::from_secs(5),
    )
    .await
    .map_err(|e| AttachError::Transient(e.to_string()))?;

    let mut channel = handle
        .channel_open_session()
        .await
        .map_err(|e| AttachError::Transient(e.to_string()))?;

    channel
        .request_subsystem(true, SUBSYSTEM_NAME)
        .await
        .map_err(|e| AttachError::Transient(e.to_string()))?;
    if !wait_subsystem_accepted(&mut channel).await {
        return Err(AttachError::Transient(
            "subsystem meshharbor-pty@v1 refused during reconnect".into(),
        ));
    }

    let mut decoder = FrameDecoder::new();
    let hello = match read_wire_from_channel(&mut channel, &mut decoder, Duration::from_secs(5))
        .await
        .map_err(|e| AttachError::Transient(e.to_string()))?
    {
        Some(WireFrame::Hello(h)) => h,
        other => {
            return Err(AttachError::Transient(format!(
                "expected Hello on reconnect, got {other:?}"
            )));
        }
    };

    let mut client_nonce = [0u8; 32];
    rand::rng().fill_bytes(&mut client_nonce);
    let proof = compute_client_proof(
        resume_secret,
        &stored.sid,
        &hello.server_nonce,
        &client_nonce,
        host_key_fp,
        client_key_fp,
    );

    send_wire_to_channel(
        &channel,
        &WireFrame::Attach(AttachFrame {
            session_id: stored.sid,
            client_nonce,
            proof,
            last_rx: stored.last_rx,
            last_rx_stderr: 0,
            c2s_next: stored.c2s_next,
            cols,
            rows,
        }),
    )
    .await
    .map_err(|e| AttachError::Transient(e.to_string()))?;

    match read_wire_from_channel(&mut channel, &mut decoder, Duration::from_secs(5))
        .await
        .map_err(|e| AttachError::Transient(e.to_string()))?
    {
        Some(WireFrame::Attached(a)) => {
            if !verify_server_proof(
                resume_secret,
                &stored.sid,
                &client_nonce,
                &hello.server_nonce,
                &a.server_proof,
            ) {
                return Err(AttachError::Transient(
                    "target failed mutual resume proof verification".into(),
                ));
            }
            Ok((handle, channel, decoder, a))
        }
        Some(WireFrame::Refused(reason)) if reason.is_terminal() => {
            Err(AttachError::TerminalRefused(reason))
        }
        Some(WireFrame::Refused(reason)) => Err(AttachError::Transient(format!("{reason:?}"))),
        other => Err(AttachError::Transient(format!(
            "unexpected attach reply: {other:?}"
        ))),
    }
}

enum ConnState {
    Attached {
        handle: russh::client::Handle<PinnedHostKey>,
        channel: russh::Channel<russh::client::Msg>,
        decoder: FrameDecoder,
        last_rx_at: Instant,
        last_ping_at: Instant,
    },
    Reconnecting {
        reason: OverlayReason,
        disconnected_at: Instant,
        attempt: usize,
        next_try_at: Instant,
        fast_cadence: bool,
    },
}

#[allow(clippy::too_many_arguments)]
async fn run_interactive_loop(
    mut stored: StoredSession,
    expected_host_key: PublicKey,
    host_key_fp: String,
    client_key_fp: String,
    session_key: PrivateKey,
    resume_secret: [u8; 32],
    ephemeral: bool,
    initial: Option<(
        russh::client::Handle<PinnedHostKey>,
        russh::Channel<russh::client::Msg>,
        FrameDecoder,
    )>,
) -> Result<i32> {
    let zh = prefers_zh();
    let (mut cols, mut rows) = current_tty_size();
    let mut shadow_vt = VtScreenTracker::new(cols, rows, 0);
    let mut c2s_queue = C2sClientQueue::new(MAX_C2S_QUEUE_BYTES);
    let mut filter = InputFilter::new();
    let mut raw_guard = RawModeGuard::enter(&stored.device);

    // Spawn local stdin reader thread so reads never stall async timers/reconnect.
    let (stdin_tx, mut stdin_rx) = mpsc::channel::<Vec<u8>>(64);
    spawn_stdin_reader(stdin_tx);

    // Resize watcher (SIGWINCH on Unix; 250 ms console-size poll on Windows).
    let (resize_tx, mut resize_rx) = mpsc::channel::<(u16, u16)>(16);
    spawn_resize_watcher(resize_tx, cols, rows);

    let now = Instant::now();
    let mut state = match initial {
        Some((handle, channel, decoder)) => ConnState::Attached {
            handle,
            channel,
            decoder,
            last_rx_at: now,
            last_ping_at: now,
        },
        None => ConnState::Reconnecting {
            reason: OverlayReason::NetworkReconnecting,
            disconnected_at: now,
            attempt: 0,
            next_try_at: now,
            fast_cadence: false,
        },
    };

    let mut overlay_visible = false;
    let mut tick = tokio::time::interval(Duration::from_millis(250));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

    let mut exit_code: i32 = 0;
    let mut post_exit_msg: Option<String> = None;

    loop {
        match &mut state {
            ConnState::Attached {
                handle,
                channel,
                decoder,
                last_rx_at,
                last_ping_at,
            } => {
                // Drain any already-buffered frames in `decoder` first.
                let mut drop_to_reconnect: Option<OverlayReason> = None;
                let mut exit_now: Option<i32> = None;

                while let Ok(Some(frame)) = decoder.next_wire() {
                    *last_rx_at = Instant::now();
                    match frame {
                        WireFrame::Data { stream, seq, bytes }
                            if stream == STREAM_STDOUT
                                && seq + bytes.len() as u64 > stored.last_rx =>
                        {
                            let skip = stored.last_rx.saturating_sub(seq) as usize;
                            if skip < bytes.len() {
                                let fresh = &bytes[skip..];
                                shadow_vt.process(fresh);
                                write_stdout_all(fresh);
                                stored.last_rx = seq + bytes.len() as u64;
                                let _ = send_wire_to_channel(
                                    channel,
                                    &WireFrame::Ack {
                                        stream: STREAM_STDOUT,
                                        upto: stored.last_rx,
                                    },
                                )
                                .await;
                            }
                        }
                        WireFrame::Snapshot { at_seq, bytes, .. } => {
                            shadow_vt.process(&bytes);
                            write_stdout_all(&bytes);
                            stored.last_rx = at_seq;
                            let _ = send_wire_to_channel(
                                channel,
                                &WireFrame::Ack {
                                    stream: STREAM_STDOUT,
                                    upto: stored.last_rx,
                                },
                            )
                            .await;
                        }
                        WireFrame::Ack { stream, upto } if stream == STREAM_STDIN => {
                            c2s_queue.ack(upto);
                            stored.c2s_next = c2s_queue.next_seq();
                        }
                        WireFrame::Ping { t_ms } => {
                            let _ = send_wire_to_channel(channel, &WireFrame::Pong { t_ms }).await;
                        }
                        WireFrame::Pong { .. } => {}
                        WireFrame::Notice(NoticeKind::TargetRestarting {
                            reason,
                            to_version,
                            ..
                        }) => {
                            let ov = if reason == "update" || to_version.is_some() {
                                OverlayReason::TargetUpdating { to_version }
                            } else {
                                OverlayReason::TargetRestarting
                            };
                            drop_to_reconnect = Some(ov);
                            break;
                        }
                        WireFrame::Notice(NoticeKind::Superseded) => {
                            post_exit_msg = Some(if zh {
                                "meshharbor: 该会话已被新的连接接管。".into()
                            } else {
                                "meshharbor: session superseded by a newer attachment.".into()
                            });
                            exit_now = Some(0);
                            break;
                        }
                        WireFrame::Notice(NoticeKind::DeadlineSoon { .. }) => {}
                        WireFrame::Exited(status) => {
                            let _ = send_wire_to_channel(
                                channel,
                                &WireFrame::Ack {
                                    stream: STREAM_STDOUT,
                                    upto: stored.last_rx,
                                },
                            )
                            .await;
                            if !ephemeral {
                                store::delete(&stored.sid);
                            }
                            exit_now = Some(status.ssh_exit_code());
                            break;
                        }
                        WireFrame::Refused(reason) => {
                            if !ephemeral {
                                store::delete(&stored.sid);
                            }
                            post_exit_msg = Some(format!(
                                "meshharbor: {}",
                                format_refuse(&reason, zh)
                            ));
                            exit_now = Some(match reason {
                                RefuseReason::Ended { status } => status.ssh_exit_code(),
                                _ => 255,
                            });
                            break;
                        }
                        _ => {}
                    }
                }

                if let Some(code) = exit_now {
                    exit_code = code;
                    let _ = handle
                        .disconnect(russh::Disconnect::ByApplication, "", "")
                        .await;
                    break;
                }
                if let Some(reason) = drop_to_reconnect {
                    let fast = matches!(
                        reason,
                        OverlayReason::TargetUpdating { .. } | OverlayReason::TargetRestarting
                    );
                    if !ephemeral {
                        let _ = store::save(&stored);
                    }
                    state = ConnState::Reconnecting {
                        reason,
                        disconnected_at: Instant::now(),
                        attempt: 0,
                        next_try_at: Instant::now() + Duration::from_millis(if fast { 800 } else { 0 }),
                        fast_cadence: fast,
                    };
                    continue;
                }

                tokio::select! {
                    msg = channel.wait() => {
                        match msg {
                            Some(russh::ChannelMsg::Data { data }) => {
                                *last_rx_at = Instant::now();
                                decoder.push(&data);
                            }
                            Some(russh::ChannelMsg::ExtendedData { .. }) => {
                                *last_rx_at = Instant::now();
                            }
                            None | Some(russh::ChannelMsg::Eof) | Some(russh::ChannelMsg::Close) => {
                                if !ephemeral {
                                    let _ = store::save(&stored);
                                }
                                state = ConnState::Reconnecting {
                                    reason: OverlayReason::NetworkReconnecting,
                                    disconnected_at: Instant::now(),
                                    attempt: 0,
                                    next_try_at: Instant::now(),
                                    fast_cadence: false,
                                };
                            }
                            _ => {}
                        }
                    }
                    Some(raw) = stdin_rx.recv() => {
                        let actions = filter.feed(&raw, true, Instant::now());
                        let mut should_break = false;
                        for act in actions {
                            match act {
                                FilterAction::Forward(bytes) => {
                                    if let Some((seq, chunk)) = c2s_queue.push(&bytes) {
                                        stored.c2s_next = c2s_queue.next_seq();
                                        let _ = send_wire_to_channel(
                                            channel,
                                            &WireFrame::Data {
                                                stream: STREAM_STDIN,
                                                seq,
                                                bytes: chunk,
                                            },
                                        )
                                        .await;
                                    }
                                }
                                FilterAction::Detach => {
                                    let _ = send_wire_to_channel(channel, &WireFrame::Detach).await;
                                    if !ephemeral {
                                        let _ = store::save(&stored);
                                    }
                                    post_exit_msg = Some(format_detach_hint(&stored, zh));
                                    exit_code = 0;
                                    should_break = true;
                                    break;
                                }
                                FilterAction::Terminate => {
                                    let _ = send_wire_to_channel(channel, &WireFrame::Terminate).await;
                                    if !ephemeral {
                                        store::delete(&stored.sid);
                                    }
                                    post_exit_msg = Some(if zh {
                                        "meshharbor: 已结束远端 SSH 会话。".into()
                                    } else {
                                        "meshharbor: remote SSH session terminated.".into()
                                    });
                                    exit_code = 0;
                                    should_break = true;
                                    break;
                                }
                                FilterAction::Help => {
                                    let help = if zh {
                                        "\r\n\x1b[2mMeshHarbor SSH 转义快捷键（回车后输入）: ~d 后台挂起 · ~. 结束远端会话 · ~~ 输入 ~ · ~? 帮助\x1b[0m\r\n"
                                    } else {
                                        "\r\n\x1b[2mMeshHarbor SSH escapes (after newline): ~d detach · ~. terminate remote · ~~ literal ~ · ~? help\x1b[0m\r\n"
                                    };
                                    write_stdout_all(help.as_bytes());
                                }
                                _ => {}
                            }
                        }
                        if should_break {
                            let _ = handle
                                .disconnect(russh::Disconnect::ByApplication, "", "")
                                .await;
                            break;
                        }
                    }
                    Some((new_c, new_r)) = resize_rx.recv() => {
                        cols = new_c;
                        rows = new_r;
                        shadow_vt.resize(cols, rows);
                        let _ = send_wire_to_channel(channel, &WireFrame::Resize { cols, rows }).await;
                    }
                    _ = tick.tick() => {
                        let now = Instant::now();
                        let silent = now.saturating_duration_since(*last_rx_at);
                        if silent >= HARD_DROP_AFTER {
                            if !ephemeral {
                                let _ = store::save(&stored);
                            }
                            state = ConnState::Reconnecting {
                                reason: OverlayReason::NetworkReconnecting,
                                disconnected_at: now,
                                attempt: 0,
                                next_try_at: now,
                                fast_cadence: false,
                            };
                            continue;
                        }
                        if silent >= SUSPECT_AFTER {
                            // Paint subtle suspect overlay and attempt make-before-break dial!
                            let bar = render_banner_ansi(
                                &stored.device,
                                &OverlayReason::LinkSuspect,
                                silent.as_secs(),
                                c2s_queue.buffered_len(),
                                false,
                                cols,
                                zh,
                            );
                            write_stdout_all(&bar);
                            overlay_visible = true;

                            if let Ok((new_h, new_ch, new_dec, attached_info)) = dial_and_attach(
                                &stored,
                                &expected_host_key,
                                &session_key,
                                &resume_secret,
                                &host_key_fp,
                                &client_key_fp,
                                cols,
                                rows,
                            ).await {
                                c2s_queue.ack(attached_info.c2s_acked);
                                for (seq, chunk) in c2s_queue.unacked_chunks(MAX_DATA_CHUNK) {
                                    let _ = send_wire_to_channel(
                                        &new_ch,
                                        &WireFrame::Data { stream: STREAM_STDIN, seq, bytes: chunk },
                                    ).await;
                                }
                                let _ = send_wire_to_channel(&new_ch, &WireFrame::Resize { cols, rows }).await;
                                if overlay_visible {
                                    if let Some(restore) = shadow_vt.render_top_row_restore() {
                                        write_stdout_all(&restore);
                                    }
                                    write_stdout_all(&restore_title_ansi(&stored.device));
                                    overlay_visible = false;
                                }
                                state = ConnState::Attached {
                                    handle: new_h,
                                    channel: new_ch,
                                    decoder: new_dec,
                                    last_rx_at: Instant::now(),
                                    last_ping_at: Instant::now(),
                                };
                                continue;
                            }
                        } else if now.saturating_duration_since(*last_ping_at) >= PING_EVERY {
                            *last_ping_at = now;
                            let _ = send_wire_to_channel(
                                channel,
                                &WireFrame::Ping { t_ms: now_unix_ms() },
                            )
                            .await;
                        }
                    }
                }
            }

            ConnState::Reconnecting {
                reason,
                disconnected_at,
                attempt,
                next_try_at,
                fast_cadence,
            } => {
                if now_unix_ms() >= stored.deadline_ms {
                    if !ephemeral {
                        store::delete(&stored.sid);
                    }
                    post_exit_msg = Some(if zh {
                        "meshharbor: 远端 SSH 会话已到达最大有效期，停止恢复。".into()
                    } else {
                        "meshharbor: remote SSH session reached its granted deadline.".into()
                    });
                    exit_code = 255;
                    break;
                }

                let now = Instant::now();
                let elapsed = now.saturating_duration_since(*disconnected_at);
                let show_now = elapsed >= OVERLAY_SHOW_DELAY
                    || matches!(
                        reason,
                        OverlayReason::TargetUpdating { .. } | OverlayReason::TargetRestarting
                    )
                    || filter.is_ctrl_c_armed(now);

                if show_now {
                    let bar = render_banner_ansi(
                        &stored.device,
                        reason,
                        elapsed.as_secs(),
                        c2s_queue.buffered_len(),
                        filter.is_ctrl_c_armed(now),
                        cols,
                        zh,
                    );
                    write_stdout_all(&bar);
                    overlay_visible = true;
                }

                let wait_until = tokio::time::Instant::from_std(*next_try_at);
                tokio::select! {
                    _ = tokio::time::sleep_until(wait_until) => {
                        match dial_and_attach(
                            &stored,
                            &expected_host_key,
                            &session_key,
                            &resume_secret,
                            &host_key_fp,
                            &client_key_fp,
                            cols,
                            rows,
                        )
                        .await
                        {
                            Ok((new_h, new_ch, new_dec, attached_info)) => {
                                filter.clear_ctrl_c_arm();
                                c2s_queue.ack(attached_info.c2s_acked);
                                for (seq, chunk) in c2s_queue.unacked_chunks(MAX_DATA_CHUNK) {
                                    let _ = send_wire_to_channel(
                                        &new_ch,
                                        &WireFrame::Data {
                                            stream: STREAM_STDIN,
                                            seq,
                                            bytes: chunk,
                                        },
                                    )
                                    .await;
                                }
                                let _ = send_wire_to_channel(
                                    &new_ch,
                                    &WireFrame::Resize { cols, rows },
                                )
                                .await;
                                // Seamlessly repaint original top row from shadow vt100!
                                if overlay_visible {
                                    if let Some(restore) = shadow_vt.render_top_row_restore() {
                                        write_stdout_all(&restore);
                                    }
                                    write_stdout_all(&restore_title_ansi(&stored.device));
                                    overlay_visible = false;
                                }
                                state = ConnState::Attached {
                                    handle: new_h,
                                    channel: new_ch,
                                    decoder: new_dec,
                                    last_rx_at: Instant::now(),
                                    last_ping_at: Instant::now(),
                                };
                            }
                            Err(AttachError::TerminalRefused(ref_reason)) => {
                                if !ephemeral {
                                    store::delete(&stored.sid);
                                }
                                exit_code = match &ref_reason {
                                    RefuseReason::Ended { status } => status.ssh_exit_code(),
                                    _ => 255,
                                };
                                post_exit_msg = Some(format!(
                                    "meshharbor: {}",
                                    format_refuse(&ref_reason, zh)
                                ));
                                break;
                            }
                            Err(AttachError::Transient(_)) => {
                                *attempt = attempt.saturating_add(1);
                                let base_ms = if *fast_cadence {
                                    1000
                                } else {
                                    BACKOFF_MS[(*attempt).min(BACKOFF_MS.len() - 1)]
                                };
                                // Small deterministic jitter (0..150 ms).
                                let jitter = (now_unix_ms() % 150) as u64;
                                *next_try_at = Instant::now() + Duration::from_millis(base_ms + jitter);
                            }
                        }
                    }
                    Some(raw) = stdin_rx.recv() => {
                        let actions = filter.feed(&raw, false, Instant::now());
                        let mut should_break = false;
                        for act in actions {
                            match act {
                                FilterAction::Forward(bytes) => {
                                    let _ = c2s_queue.push(&bytes);
                                    stored.c2s_next = c2s_queue.next_seq();
                                }
                                FilterAction::CtrlCFirstQueued => {
                                    // Immediately repaint banner with double-Ctrl-C warning!
                                    let bar = render_banner_ansi(
                                        &stored.device,
                                        reason,
                                        elapsed.as_secs(),
                                        c2s_queue.buffered_len(),
                                        true,
                                        cols,
                                        zh,
                                    );
                                    write_stdout_all(&bar);
                                    overlay_visible = true;
                                }
                                FilterAction::CtrlCDoubleDetach => {
                                    c2s_queue.drop_trailing_ctrl_c();
                                    if !ephemeral {
                                        let _ = store::save(&stored);
                                    }
                                    post_exit_msg = Some(format_detach_hint(&stored, zh));
                                    exit_code = 0;
                                    should_break = true;
                                    break;
                                }
                                FilterAction::Detach => {
                                    if !ephemeral {
                                        let _ = store::save(&stored);
                                    }
                                    post_exit_msg = Some(format_detach_hint(&stored, zh));
                                    exit_code = 0;
                                    should_break = true;
                                    break;
                                }
                                FilterAction::Terminate => {
                                    if !ephemeral {
                                        let _ = store::save(&stored);
                                    }
                                    post_exit_msg = Some(if zh {
                                        format!(
                                            "meshharbor: 当前无法联系远端设备，远端进程仍在后台运行。\n  恢复: mh ssh {} --resume {}\n  结束: mh ssh {} --kill {}",
                                            stored.device,
                                            stored.sid.short_hex(),
                                            stored.device,
                                            stored.sid.short_hex()
                                        )
                                    } else {
                                        format!(
                                            "meshharbor: remote unreachable — process is still running.\n  Resume: mh ssh {} --resume {}\n  Kill:   mh ssh {} --kill {}",
                                            stored.device,
                                            stored.sid.short_hex(),
                                            stored.device,
                                            stored.sid.short_hex()
                                        )
                                    });
                                    exit_code = 0;
                                    should_break = true;
                                    break;
                                }
                                FilterAction::Help => {}
                            }
                        }
                        if should_break {
                            break;
                        }
                    }
                    Some((new_c, new_r)) = resize_rx.recv() => {
                        cols = new_c;
                        rows = new_r;
                        shadow_vt.resize(cols, rows);
                    }
                    _ = tick.tick() => {}
                }
            }
        }
    }

    if overlay_visible
        && let Some(restore) = shadow_vt.render_top_row_restore()
    {
        write_stdout_all(&restore);
    }
    raw_guard.restore_now();
    if let Some(msg) = post_exit_msg {
        eprintln!("\n{msg}");
    }
    Ok(exit_code)
}

/// Classic `pty-req + shell` fallback on an ALREADY-authenticated `russh` handle
/// (used when a target daemon < 0.4.219 refuses `meshharbor-pty@v1`).
async fn run_classic_fallback(
    handle: russh::client::Handle<PinnedHostKey>,
    device: &str,
    term: &str,
    cols: u16,
    rows: u16,
    command: Option<String>,
) -> Result<i32> {
    let mut channel = handle
        .channel_open_session()
        .await
        .context("opening fallback classic SSH channel")?;
    channel
        .request_pty(true, term, u32::from(cols), u32::from(rows), 0, 0, &[])
        .await
        .context("requesting classic PTY")?;
    match command {
        Some(cmd) => channel.exec(true, cmd).await.context("starting classic exec")?,
        None => channel.request_shell(true).await.context("starting classic shell")?,
    }

    let mut raw_guard = RawModeGuard::enter(device);
    let (stdin_tx, mut stdin_rx) = mpsc::channel::<Vec<u8>>(64);
    spawn_stdin_reader(stdin_tx);
    let (resize_tx, mut resize_rx) = mpsc::channel::<(u16, u16)>(16);
    spawn_resize_watcher(resize_tx, cols, rows);

    let mut exit_code: i32 = 0;
    loop {
        tokio::select! {
            msg = channel.wait() => {
                match msg {
                    Some(russh::ChannelMsg::Data { data }) => write_stdout_all(&data),
                    Some(russh::ChannelMsg::ExtendedData { data, .. }) => {
                        let _ = std::io::stderr().write_all(&data);
                        let _ = std::io::stderr().flush();
                    }
                    Some(russh::ChannelMsg::ExitStatus { exit_status }) => {
                        exit_code = exit_status as i32;
                    }
                    None | Some(russh::ChannelMsg::Close) => break,
                    _ => {}
                }
            }
            Some(bytes) = stdin_rx.recv() => {
                if channel.data(&bytes[..]).await.is_err() {
                    break;
                }
            }
            Some((c, r)) = resize_rx.recv() => {
                let _ = channel.window_change(u32::from(c), u32::from(r), 0, 0).await;
            }
        }
    }

    raw_guard.restore_now();
    let _ = handle
        .disconnect(russh::Disconnect::ByApplication, "", "")
        .await;
    Ok(exit_code)
}

async fn wait_subsystem_accepted(channel: &mut russh::Channel<russh::client::Msg>) -> bool {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while tokio::time::Instant::now() < deadline {
        match tokio::time::timeout(Duration::from_secs(5), channel.wait()).await {
            Ok(Some(russh::ChannelMsg::Success)) => return true,
            Ok(Some(russh::ChannelMsg::Failure))
            | Ok(Some(russh::ChannelMsg::Close))
            | Ok(Some(russh::ChannelMsg::Eof))
            | Ok(None)
            | Err(_) => return false,
            _ => continue,
        }
    }
    false
}

async fn send_wire_to_channel(
    channel: &russh::Channel<russh::client::Msg>,
    frame: &WireFrame,
) -> Result<()> {
    let raw = frame.encode().context("encoding wire frame")?;
    channel
        .data(&raw[..])
        .await
        .map_err(|e| anyhow!("sending wire frame over SSH channel: {e}"))
}

async fn read_wire_from_channel(
    channel: &mut russh::Channel<russh::client::Msg>,
    decoder: &mut FrameDecoder,
    timeout: Duration,
) -> Result<Option<WireFrame>> {
    tokio::time::timeout(timeout, async {
        loop {
            if let Some(f) = decoder.next_wire()? {
                return Ok(Some(f));
            }
            match channel.wait().await {
                Some(russh::ChannelMsg::Data { data }) => decoder.push(&data),
                Some(russh::ChannelMsg::Eof) | Some(russh::ChannelMsg::Close) | None => {
                    return Ok(None);
                }
                _ => {}
            }
        }
    })
    .await
    .context("timed out waiting for wire frame")?
}

fn current_tty_size() -> (u16, u16) {
    terminal::size().unwrap_or((80, 24))
}

fn collect_local_env() -> Vec<(String, String)> {
    let mut out = Vec::new();
    for (k, v) in std::env::vars() {
        if k == "LANG" || k == "TZ" || k == "COLORTERM" || k.starts_with("LC_") {
            out.push((k, v));
        }
    }
    meshharbor_node_core::pty_resume::filter_open_env(&out)
}

fn write_stdout_all(bytes: &[u8]) {
    let mut out = std::io::stdout().lock();
    let _ = out.write_all(bytes);
    let _ = out.flush();
}

fn spawn_stdin_reader(tx: mpsc::Sender<Vec<u8>>) {
    std::thread::spawn(move || {
        use std::io::Read;
        let mut stdin = std::io::stdin().lock();
        let mut buf = [0u8; 4096];
        loop {
            match stdin.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if tx.blocking_send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
            }
        }
    });
}

fn spawn_resize_watcher(tx: mpsc::Sender<(u16, u16)>, initial_cols: u16, initial_rows: u16) {
    tokio::spawn(async move {
        let mut last = (initial_cols, initial_rows);
        #[cfg(unix)]
        {
            if let Ok(mut sig) =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change())
            {
                while sig.recv().await.is_some() {
                    let cur = current_tty_size();
                    if cur != last {
                        last = cur;
                        if tx.send(cur).await.is_err() {
                            break;
                        }
                    }
                }
                return;
            }
        }
        // Fallback polling (Windows console + non-signal Unix).
        let mut iv = tokio::time::interval(Duration::from_millis(250));
        loop {
            iv.tick().await;
            let cur = current_tty_size();
            if cur != last {
                last = cur;
                if tx.send(cur).await.is_err() {
                    break;
                }
            }
        }
    });
}

fn format_detach_hint(stored: &StoredSession, zh: bool) -> String {
    if zh {
        format!(
            "meshharbor: 已在后台保留远端 SSH 会话 {}（进程继续运行）。\n  重新接回: mh ssh {} --resume {}\n  手动结束: mh ssh {} --kill {}",
            stored.sid.short_hex(),
            stored.device,
            stored.sid.short_hex(),
            stored.device,
            stored.sid.short_hex(),
        )
    } else {
        format!(
            "meshharbor: detached from remote SSH session {} (remote process keeps running).\n  Resume: mh ssh {} --resume {}\n  Kill:   mh ssh {} --kill {}",
            stored.sid.short_hex(),
            stored.device,
            stored.sid.short_hex(),
            stored.device,
            stored.sid.short_hex(),
        )
    }
}

fn format_refuse(reason: &RefuseReason, zh: bool) -> String {
    match reason {
        RefuseReason::UnknownSession => {
            if zh {
                "远端会话已不存在（可能已重启前结束或超时回收）。".into()
            } else {
                "remote session no longer exists.".into()
            }
        }
        RefuseReason::BadProof => {
            if zh {
                "会话恢复凭证校验失败。".into()
            } else {
                "resume proof verification failed.".into()
            }
        }
        RefuseReason::Expired => {
            if zh {
                "会话已超过授权有效期。".into()
            } else {
                "session has expired.".into()
            }
        }
        RefuseReason::Revoked { detail } => {
            if zh {
                format!("会话已被撤销（{detail}）。")
            } else {
                format!("session revoked ({detail}).")
            }
        }
        RefuseReason::Ended { status } => {
            if zh {
                format!("远端会话已正常结束（退出码 {}）。", status.ssh_exit_code())
            } else {
                format!("remote session ended (exit code {}).", status.ssh_exit_code())
            }
        }
        RefuseReason::Policy { detail } => detail.clone(),
        RefuseReason::Busy { detail } => detail.clone(),
        RefuseReason::UnsupportedProto { server_max } => {
            format!("unsupported protocol version (target max v{server_max})")
        }
        RefuseReason::Internal { detail } => detail.clone(),
    }
}
