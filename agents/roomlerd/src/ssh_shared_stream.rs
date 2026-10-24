// SPDX-License-Identifier: MPL-2.0
//! Restricted in-process SSH over a task-owned, one-use stream, not a host SSH
//! listener or arbitrary TCP destination. The caller supplies an already-authorized
//! exact grant; this module never assigns tenant membership or routes a subnet.
use anyhow::{Context as _, Result, bail};
use roomler_ai_remote_control::models::{ConsentMode, SshAccountMode, ssh_limits};
use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::{TcpListener, TcpStream},
};
use tokio_util::sync::CancellationToken;

/// Fields are explicit so the upcoming share PDP bridge cannot accidentally
/// inherit the device-wide authorized-key list or enable a generic forward.
pub struct SharedSshSpec {
    pub grant_id: String,
    pub public_key: String,
    pub caller: String,
    pub account_mode: SshAccountMode,
    pub account: Option<String>,
    pub consent_mode: Option<ConsentMode>,
    pub expires_at_ms: u64,
    pub session_secs: u64,
}
/// Prepared once, consumed once. The grant is private to this stream; it never
/// enters the process-global GRANTS table or authenticates an overlay SSH port.
pub struct SharedSshStream {
    ctx: Arc<crate::ssh::sshd::Ctx>,
    grant: crate::ssh::Grant,
}
impl SharedSshStream {
    pub fn prepare(
        cfg: &crate::config::AgentConfig,
        services: crate::ssh::SessionServices,
        spec: SharedSshSpec,
    ) -> Result<Self> {
        if !cfg.ssh_enabled {
            bail!("the device has not enabled its embedded SSH service");
        }
        if spec.grant_id.is_empty()
            || spec.grant_id.len() > 128
            || spec.caller.len() > 256
            || spec.public_key.len() > 1024
        {
            bail!("invalid bounded shared SSH grant");
        }
        let key = russh::keys::ssh_key::PublicKey::from_openssh(&spec.public_key)
            .context("shared SSH public key")?;
        if key.algorithm() != russh::keys::ssh_key::Algorithm::Ed25519 {
            bail!("shared SSH requires an Ed25519 key");
        }
        let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as u64;
        let window = Duration::from_millis(spec.expires_at_ms.saturating_sub(now))
            .min(Duration::from_secs(ssh_limits::GRANT_TTL_SECS));
        if window.is_zero() {
            bail!("shared SSH grant has expired");
        }
        if spec.account_mode == SshAccountMode::Named
            && spec.account.as_ref().is_none_or(|s| s.trim().is_empty())
        {
            bail!("named SSH account missing");
        }
        let ctx = crate::ssh::sshd::Ctx::build(cfg, services)
            .context("device has no usable embedded SSH host key")?;
        let grant = crate::ssh::Grant::for_shared_stream(
            spec.grant_id,
            spec.public_key,
            spec.caller,
            spec.account_mode.wire().into(),
            spec.account,
            Some(if spec.consent_mode == Some(ConsentMode::Auto) {
                ConsentMode::Auto
            } else {
                ConsentMode::Prompt
            }),
            ssh_limits::clamp_session_secs(spec.session_secs),
            Instant::now() + window,
        );
        Ok(Self { ctx, grant })
    }
    pub async fn serve<S>(self, stream: S, peer: std::net::SocketAddr, cancel: CancellationToken)
    where
        S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
    {
        let _live = crate::ssh::LiveConnection::open();
        let transport = CancelStream::new(stream, cancel.clone());
        let handler =
            crate::ssh::sshd::Handler::new_shared(self.ctx.clone(), peer, self.grant, cancel);
        if let Ok(session) =
            russh::server::run_stream(self.ctx.config.clone(), transport, handler).await
        {
            let _ = session.await;
        }
    }
    /// Only adaptation for run_flow's existing TcpStream signature. Both ends
    /// belong to this task; any local race is rejected, never served. No generic
    /// 127.0.0.1:22, persistent endpoint, or externally-bound SSH service exists.
    pub async fn socket_pair(self, cancel: CancellationToken) -> Result<TcpStream> {
        let (client, server, peer) = tokio::time::timeout(Duration::from_secs(1), async {
            let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
            let addr = listener.local_addr()?;
            let (client, (server, peer)) =
                tokio::try_join!(TcpStream::connect(addr), listener.accept())?;
            if peer != client.local_addr()? || server.local_addr()? != client.peer_addr()? {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "one-shot SSH socketpair peer mismatch",
                ));
            }
            drop(listener);
            Ok::<_, std::io::Error>((client, server, peer))
        })
        .await
        .context("one-shot SSH socketpair timeout")??;
        tokio::spawn(self.serve(server, peer, cancel));
        Ok(client)
    }
}
/// Used by the actual PTY consent path: expiry while a human is deciding
/// cannot return late approval and start a fresh process after authority ended.
pub(crate) async fn while_authorized<T>(
    cancel: Option<&CancellationToken>,
    future: impl Future<Output = Result<T, String>>,
) -> Result<T, String> {
    match cancel {
        Some(cancel) => {
            tokio::select! {biased;_ = cancel.cancelled()=>Err("shared SSH lease ended".into()), result=future=>result}
        }
        None => future.await,
    }
}
/// A lease cancellation wakes an idle SSH read immediately (EOF) and refuses
/// every later write. Closing only the tunnel signalling socket is insufficient.
struct CancelStream<S> {
    inner: S,
    read_cancel: Pin<Box<dyn Future<Output = ()> + Send>>,
    write_cancel: Pin<Box<dyn Future<Output = ()> + Send>>,
}
impl<S> CancelStream<S> {
    fn new(inner: S, cancel: CancellationToken) -> Self {
        Self {
            inner,
            read_cancel: Box::pin(cancel.clone().cancelled_owned()),
            write_cancel: Box::pin(cancel.cancelled_owned()),
        }
    }
}
impl<S: AsyncRead + Unpin> AsyncRead for CancelStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.read_cancel.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Ok(()));
        }
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for CancelStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        if self.write_cancel.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Err(std::io::ErrorKind::BrokenPipe.into()));
        }
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use russh::keys::ssh_key::private::{Ed25519Keypair, PrivateKey};
    fn key(seed: u8) -> PrivateKey {
        PrivateKey::from(Ed25519Keypair::from_seed(&[seed; 32]))
    }
    fn spec(key: &PrivateKey) -> SharedSshSpec {
        SharedSshSpec {
            grant_id: "shared-stream-fixture".into(),
            public_key: key.public_key().to_openssh().unwrap(),
            caller: "approved-recipient/share-fixture".into(),
            account_mode: SshAccountMode::Daemon,
            account: None,
            consent_mode: Some(ConsentMode::Auto),
            expires_at_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_millis() as u64
                + 30_000,
            session_secs: 30,
        }
    }
    fn prepared(key: &PrivateKey, listed: Option<&PrivateKey>) -> SharedSshStream {
        prepared_with_streaming(key, listed, true)
    }
    fn prepared_with_streaming(
        key: &PrivateKey,
        listed: Option<&PrivateKey>,
        streaming: bool,
    ) -> SharedSshStream {
        let mut cfg = crate::config::test_fixture();
        cfg.ssh_enabled = true;
        cfg.ssh_exec_streaming = streaming;
        cfg.ssh_host_key = Some(crate::ssh::generate_host_key().unwrap());
        cfg.ssh_account_mode = Some("daemon".into());
        cfg.ssh_authorized_keys = listed
            .map(|k| vec![k.public_key().to_openssh().unwrap()])
            .unwrap_or_default();
        let services = crate::ssh::SessionServices {
            power_activity: None,
            asker: crate::ssh::Asker::Here {
                broker: crate::consent::ConsentBroker::new(
                    crate::consent::Mode::AutoGrant,
                    tempfile::tempdir().unwrap().keep(),
                )
                .unwrap(),
                indicator: crate::indicator::ViewerIndicator::disabled(),
            },
            activity: None,
        };
        SharedSshStream::prepare(&cfg, services, spec(key)).unwrap()
    }
    struct Client;
    impl russh::client::Handler for Client {
        type Error = russh::Error;
        async fn check_server_key(
            &mut self,
            _: &russh::keys::ssh_key::PublicKey,
        ) -> Result<bool, Self::Error> {
            Ok(true)
        }
    }
    async fn connect(stream: TcpStream) -> russh::client::Handle<Client> {
        russh::client::connect_stream(Arc::new(russh::client::Config::default()), stream, Client)
            .await
            .unwrap()
    }
    async fn auth(c: &mut russh::client::Handle<Client>, k: PrivateKey) -> bool {
        let hash = c.best_supported_rsa_hash().await.unwrap().flatten();
        c.authenticate_publickey(
            "roomler",
            russh::keys::PrivateKeyWithHashAlg::new(Arc::new(k), hash),
        )
        .await
        .unwrap()
        .success()
    }
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shared_ssh_real_socketpair_exact_grant_no_key_list_fallback_or_subsystem_forward() {
        let target = key(77);
        let listed = key(78);
        let cancel = CancellationToken::new();
        let stream = prepared(&target, Some(&listed))
            .socket_pair(cancel.clone())
            .await
            .unwrap();
        assert!(
            TcpStream::connect(stream.peer_addr().unwrap())
                .await
                .is_err(),
            "one-shot adaptation leaves no SSH listener"
        );
        let mut client = connect(stream).await;
        assert!(
            !auth(&mut client, listed).await,
            "device-wide key list must not authenticate this scoped stream"
        );
        assert!(auth(&mut client, target).await);
        let mut command = client.channel_open_session().await.unwrap();
        command
            .exec(true, "echo meshharbor-shared-ssh-fixture")
            .await
            .unwrap();
        let (stdout, exit) = tokio::time::timeout(Duration::from_secs(5), async {
            let mut stdout = Vec::new();
            let mut exit = None;
            while let Some(m) = command.wait().await {
                match m {
                    russh::ChannelMsg::Data { data } => stdout.extend_from_slice(&data),
                    russh::ChannelMsg::ExitStatus { exit_status } => exit = Some(exit_status),
                    _ => {}
                }
            }
            (stdout, exit)
        })
        .await
        .unwrap();
        assert!(String::from_utf8_lossy(&stdout).contains("meshharbor-shared-ssh-fixture"));
        assert_eq!(exit, Some(0));
        assert!(
            client
                .channel_open_direct_tcpip("127.0.0.1", 22, "127.0.0.1", 12345)
                .await
                .is_err()
        );
        assert!(client.tcpip_forward("127.0.0.1", 0).await.is_err());
        let mut channel = client.channel_open_session().await.unwrap();
        channel.request_subsystem(true, "sftp").await.unwrap();
        let failure = tokio::time::timeout(Duration::from_secs(2), async {
            while let Some(m) = channel.wait().await {
                if matches!(m, russh::ChannelMsg::Failure) {
                    return true;
                }
            }
            false
        })
        .await
        .unwrap();
        assert!(failure);
        cancel.cancel();
        assert!(
            tokio::time::timeout(Duration::from_secs(2), client.channel_open_session())
                .await
                .unwrap()
                .is_err(),
            "lease cancellation ends the actual idle SSH transport"
        );
    }
    #[tokio::test]
    async fn shared_ssh_pending_consent_is_cancelled_before_late_approval_can_spawn() {
        let cancel = CancellationToken::new();
        let c = cancel.clone();
        let task = tokio::spawn(async move {
            while_authorized(Some(&c), std::future::pending::<Result<(), String>>()).await
        });
        tokio::task::yield_now().await;
        cancel.cancel();
        assert!(
            tokio::time::timeout(Duration::from_secs(1), task)
                .await
                .unwrap()
                .unwrap()
                .is_err()
        );
        assert!(
            while_authorized(Some(&cancel), async { Ok(()) })
                .await
                .is_err()
        );
        assert!(while_authorized(None, async { Ok(()) }).await.is_ok());
    }
    #[tokio::test]
    async fn shared_ssh_cancel_stream_ends_idle_read_and_refuses_later_write() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let (a, _b) = tokio::io::duplex(64);
        let cancel = CancellationToken::new();
        let mut stream = CancelStream::new(a, cancel.clone());
        let task = tokio::spawn(async move {
            let mut b = [0u8; 1];
            let n = stream.read(&mut b).await.unwrap();
            assert_eq!(n, 0);
            assert!(stream.write_all(b"x").await.is_err());
        });
        tokio::task::yield_now().await;
        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(1), task)
            .await
            .unwrap()
            .unwrap();
    }
    // Linux /proc lets the oracle distinguish an exited zombie from a running
    // process without claiming that orphaned children have been reaped by PID1.
    #[cfg(target_os = "linux")]
    fn running(pid: u32) -> bool {
        let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) else {
            return false;
        };
        !matches!(
            stat.rsplit_once(") ")
                .and_then(|(_, tail)| tail.chars().next()),
            Some('Z' | 'X')
        )
    }
    #[cfg(target_os = "linux")]
    async fn shared_process_cancel_oracle(pty: bool) {
        let target = key(if pty { 82 } else { 81 });
        let cancel = CancellationToken::new();
        let _cancel_on_panic = cancel.clone().drop_guard();
        // Deliberately disable the ordinary device's streaming setting: a
        // shared session must still stream output and honor its abort token.
        let stream = prepared_with_streaming(&target, None, false)
            .socket_pair(cancel.clone())
            .await
            .unwrap();
        let mut client = connect(stream).await;
        assert!(auth(&mut client, target).await);
        let mut ch = client.channel_open_session().await.unwrap();
        let command = "set +m; trap '' HUP; sleep 120 & child=$!; printf 'PARENT=%s CHILD=%s\\n' \"$$\" \"$child\"; wait";
        if pty {
            ch.request_pty(true, "xterm", 80, 24, 0, 0, &[])
                .await
                .unwrap();
            ch.request_shell(true).await.unwrap();
            ch.data(format!("{command}\n").as_bytes()).await.unwrap();
        } else {
            ch.exec(true, command).await.unwrap();
        }
        let (parent, child) = tokio::time::timeout(Duration::from_secs(5), async {
            let mut bytes = Vec::new();
            'found: loop {
                match ch.wait().await {
                    Some(russh::ChannelMsg::Data { data }) => {
                        bytes.extend_from_slice(&data);
                        let text = String::from_utf8_lossy(&bytes);
                        for line in text
                            .split_inclusive('\n')
                            .filter(|line| line.ends_with('\n'))
                        {
                            // Ignore the terminal's echoed command, which contains
                            // format placeholders rather than observed numeric PIDs.
                            let Some(rest) = line.trim().strip_prefix("PARENT=") else {
                                continue;
                            };
                            let Some((a, b)) = rest.split_once(" CHILD=") else {
                                continue;
                            };
                            if let (Ok(a), Ok(b)) = (a.parse::<u32>(), b.trim().parse::<u32>()) {
                                break 'found (a, b);
                            }
                        }
                    }
                    Some(_) => {}
                    None => panic!("SSH ended before reporting actual process IDs"),
                }
            }
        })
        .await
        .unwrap();
        assert!(
            running(parent) && running(child),
            "both processes must be live before revoke"
        );
        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(5), async {
            while running(parent) || running(child) {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("revocation must stop the owned parent and child, even ignoring HUP");
    }
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn shared_ssh_pty_eof_reaps_leader_only_after_killing_remaining_owned_group() {
        let mut pty = crate::pty::PtyProcess::spawn(
            Some("trap '' HUP; sleep 120 </dev/null >/dev/null 2>&1 & printf '%s\\n' \"$!\"; exit"),
            "xterm",
            crate::pty::WinSize { cols: 80, rows: 24 },
            &crate::exec::RunAs::Daemon,
        )
        .unwrap();
        pty.hard_kill_on_drop();
        let mut bytes = Vec::new();
        tokio::time::timeout(Duration::from_secs(5), async {
            let mut buf = [0u8; 128];
            loop {
                let n = pty.read(&mut buf).await.unwrap();
                if n == 0 {
                    break;
                }
                bytes.extend_from_slice(&buf[..n]);
            }
        })
        .await
        .unwrap();
        let child: u32 = String::from_utf8(bytes).unwrap().trim().parse().unwrap();
        assert!(
            running(child),
            "child intentionally survives the leader and closes its terminal fds"
        );
        let _ = pty.wait().await;
        drop(pty);
        tokio::time::timeout(Duration::from_secs(5), async {
            while running(child) {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .expect("wait must kill the still-owned group before releasing its leader PID");
    }
    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shared_ssh_buffered_setting_long_exec_revocation_kills_parent_and_child() {
        shared_process_cancel_oracle(false).await;
    }
    #[cfg(target_os = "linux")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shared_ssh_pty_hup_ignore_revocation_kills_owned_parent_and_child() {
        shared_process_cancel_oracle(true).await;
    }
}
