// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Client-side RDP session planner, per-session `127.77.x.y:0` loopback tunnel,
//! and OS credential-store integration shared by `mh rdp` (`meshharbor-cli`) and
//! `meshharbor-desktop` (RC/RDP Phase A).
//!
//! Security & trust boundaries:
//! 1. **Default OFF + Kill Switch**: Saving (`--save-credentials`) and reading
//!    (`--use-saved-credentials`) stored RDP credentials are both opt-in and
//!    OFF by default. Either `--no-saved-credentials` or
//!    `MESHHARBOR_RDP_PASSWORDLESS_DISABLED=1` immediately disables them.
//! 2. **Server Never Sees RDP Secrets**: Resolves the device via the local
//!    daemon (`meshharbor_localapi`) and opens an authorized local loopback TCP
//!    forward to the remote RDP port. No RDP username, domain, or password is
//!    ever transmitted to `meshharbord` or the coordination server.
//! 3. **No Secret in `argv`, `env`, Temp Files, `.rdp` Files, Logs, or URLs**:
//!    - Windows: Win32 Credential Manager (`CredWriteW` / `CredReadW` /
//!      `CredDeleteW` / `CredFree`) in process memory. `cmdkey /pass:` is
//!      strictly forbidden.
//!    - Linux: `secret-tool` via `stdin` pipe; `xfreerdp3` / `xfreerdp` with
//!      `/from-stdin:force` via `stdin` pipe.
//!    - macOS: `/usr/bin/security -i` via `stdin` pipe.
//! 4. **Certificate Pinning**: Target TLS certificate SHA-256 fingerprint is
//!    pinned when reported or specified via `--cert-sha256`. Flags that disable
//!    certificate verification (`/cert:ignore`, `/cert-ignore`, etc.) are
//!    refused.

use std::collections::BTreeMap;
use std::io::Write;
use std::net::SocketAddr;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use meshharbor_localapi as localapi;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::{DigitallySignedStruct, SignatureScheme};
use rustls_pki_types::{CertificateDer, ServerName, UnixTime};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Environment variable that acts as an operator/user kill switch for saved RDP
/// credentials (`1`, `true`, `yes`, `on` case-insensitively).
pub const KILL_SWITCH_ENV: &str = "MESHHARBOR_RDP_PASSWORDLESS_DISABLED";

/// Bounded wall-clock budget for the pre-`mstsc` RDP reachability / X.224 / TLS
/// certificate check (`V0028` / `V0029 §3.1`).
pub const RDP_PRECHECK_TIMEOUT: Duration = Duration::from_secs(5);

/// User-facing notice emitted when neither `--cert-sha256` nor a server-reported
/// `rdp_cert_sha256` is available, so `mstsc.exe` / OS trust store performs its
/// own certificate check (`V0028 §2`).
pub const UNPINNED_CERT_MSTSC_NOTICE: &str = "被控端未上报证书指纹，由 mstsc 自行校验证书";

/// Options configuring an RDP session launch (parsed from `mh rdp` or constructed
/// by `meshharbor-desktop`).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RdpCliOptions {
    pub target: String,
    pub user: Option<String>,
    pub domain: Option<String>,
    pub port: u16,
    /// Set when the caller explicitly passed `--port` (or an explicit port in
    /// desktop `openRdp`), overriding `ResolvedRdpDevice::rdp_port`.
    pub explicit_port: Option<u16>,
    pub cert_sha256: Option<String>,
    /// Diagnostic / headless pre-check mode (`mh rdp <target> --check`): resolves
    /// the target, opens the per-session loopback tunnel, completes X.224 + TLS
    /// certificate verification, prints the result, and exits without ever
    /// reading/writing credentials or spawning any RDP client.
    pub check: bool,
    pub save_credentials: bool,
    pub use_saved_credentials: bool,
    pub clear_credentials: bool,
    pub no_saved_credentials: bool,
    pub extra_args: Vec<String>,
}

/// Scoped key identifying a target device in the client's local OS credential
/// store (`MeshHarbor:rdp:<org_id>:<device_id>`).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct RdpCredentialScope {
    pub org_id: String,
    pub device_id: String,
}

impl RdpCredentialScope {
    pub fn store_target_name(&self) -> String {
        format!("MeshHarbor:rdp:{}:{}", self.org_id, self.device_id)
    }
}

/// Stored RDP credential in the client machine's OS secure credential store.
/// The password is redacted in `Debug` and zeroized on `Drop`.
#[derive(Clone, PartialEq, Eq)]
pub struct StoredRdpCredential {
    pub username: String,
    pub domain: Option<String>,
    password: String,
}

impl std::fmt::Debug for StoredRdpCredential {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StoredRdpCredential")
            .field("username", &self.username)
            .field("domain", &self.domain)
            .field("password", &"<redacted>")
            .finish()
    }
}

impl StoredRdpCredential {
    pub fn new(
        username: impl Into<String>,
        domain: Option<String>,
        password: impl Into<String>,
    ) -> Self {
        Self {
            username: username.into(),
            domain,
            password: password.into(),
        }
    }

    pub fn password(&self) -> &str {
        &self.password
    }

    pub fn qualified_username(&self) -> String {
        match self
            .domain
            .as_deref()
            .map(str::trim)
            .filter(|d| !d.is_empty())
        {
            Some(d) => format!("{d}\\{}", self.username),
            None => self.username.clone(),
        }
    }

    pub fn from_qualified_username(qualified: &str, password: impl Into<String>) -> Self {
        if let Some((domain, user)) = qualified.split_once('\\') {
            Self::new(
                user.to_string(),
                Some(domain.to_string()).filter(|d| !d.is_empty()),
                password,
            )
        } else {
            Self::new(qualified.to_string(), None, password)
        }
    }
}

impl Drop for StoredRdpCredential {
    fn drop(&mut self) {
        unsafe {
            for b in self.password.as_bytes_mut() {
                std::ptr::write_volatile(b, 0);
            }
        }
    }
}

/// Resolved target device metadata from the local daemon / server (never
/// includes any RDP password or secret).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ResolvedRdpDevice {
    pub org_id: String,
    pub device_id: String,
    pub device_name: String,
    pub rdp_available: Option<bool>,
    pub rdp_port: Option<u16>,
    pub rdp_cert_sha256: Option<String>,
}

static SESSION_LOOPBACK_BASE: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
static SESSION_LOOPBACK_SEQ: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

/// Allocate a unique per-session loopback IPv4 address in `127.77.x.y`
/// (`127.0.0.0/8`, never `127.0.0.1`) so Windows `TERMSRV/<ip>` session
/// credentials never collide with user-saved `TERMSRV/127.0.0.1` entries or
/// concurrent `mh rdp` / desktop sessions.
pub fn allocate_session_loopback_ip() -> std::net::Ipv4Addr {
    let base = *SESSION_LOOPBACK_BASE.get_or_init(|| {
        let pid = std::process::id() as usize;
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.subsec_nanos() as usize)
            .unwrap_or(0);
        pid.wrapping_mul(0x9E37_79B9).wrapping_add(nanos)
    });
    let seq = SESSION_LOOPBACK_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    let slot = base.wrapping_add(seq) % (254 * 254);
    let x = ((slot / 254) as u8) + 1;
    let y = ((slot % 254) as u8) + 1;
    std::net::Ipv4Addr::new(127, 77, x, y)
}

/// Bind the per-session local loopback listener the RDP client connects to.
///
/// Windows binds a unique `127.77.x.y:0`: the `TERMSRV/<ip>` credential target
/// that lets `mstsc.exe` log on without a prompt is keyed by that address, so it
/// must never collide with another session or a user-saved `127.0.0.1` entry.
/// Every other platform binds `127.0.0.1:0`. macOS configures only `127.0.0.1`
/// on `lo0`, so a `127.77.x.y` bind fails there (`EADDRNOTAVAIL`), and FreeRDP
/// keys nothing by the loopback address.
pub async fn bind_unique_session_loopback_listener() -> Result<tokio::net::TcpListener> {
    if !cfg!(windows) {
        return tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .context("failed to bind local per-session loopback listener for RDP tunnel");
    }
    let mut last_err = None;
    for _ in 0..8 {
        let ip = allocate_session_loopback_ip();
        match tokio::net::TcpListener::bind((ip, 0)).await {
            Ok(listener) => return Ok(listener),
            Err(e) => last_err = Some(e),
        }
    }
    Err(last_err.unwrap_or_else(|| {
        std::io::Error::other("failed to bind unique 127.77.x.y session loopback listener")
    }))
    .context("failed to bind local per-session loopback listener for RDP tunnel")
}

/// Minimal RFC 1928 SOCKS5 no-auth `CONNECT` handshake to a local per-agent
/// overlay netstack SOCKS5 listener (`127.0.0.1:<socks_port>`). Keeps
/// `meshharbor-node-core` completely free of `tunnel-core` transport dependencies.
async fn socks5_client_connect<S>(stream: &mut S, dst_host: &str, dst_port: u16) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    const VER: u8 = 0x05;
    const METHOD_NO_AUTH: u8 = 0x00;
    const CMD_CONNECT: u8 = 0x01;
    const ATYP_IPV4: u8 = 0x01;
    const ATYP_DOMAIN: u8 = 0x03;
    const ATYP_IPV6: u8 = 0x04;
    const REP_SUCCESS: u8 = 0x00;

    stream
        .write_all(&[VER, 0x01, METHOD_NO_AUTH])
        .await
        .context("socks client greeting")?;
    let mut sel = [0u8; 2];
    stream
        .read_exact(&mut sel)
        .await
        .context("socks client method reply")?;
    if sel != [VER, METHOD_NO_AUTH] {
        bail!("proxy rejected no-auth (got {sel:?})");
    }
    let host = dst_host.as_bytes();
    if host.len() > 255 {
        bail!("dst_host too long for SOCKS domain ATYP");
    }
    let mut req = vec![VER, CMD_CONNECT, 0x00, ATYP_DOMAIN, host.len() as u8];
    req.extend_from_slice(host);
    req.extend_from_slice(&dst_port.to_be_bytes());
    stream
        .write_all(&req)
        .await
        .context("socks client connect request")?;
    let mut head = [0u8; 4];
    stream
        .read_exact(&mut head)
        .await
        .context("socks client reply header")?;
    if head[1] != REP_SUCCESS {
        bail!("proxy CONNECT failed (REP={:#x})", head[1]);
    }
    let addr_len = match head[3] {
        ATYP_IPV4 => 4,
        ATYP_IPV6 => 16,
        ATYP_DOMAIN => {
            let mut l = [0u8; 1];
            stream
                .read_exact(&mut l)
                .await
                .context("socks client reply domain len")?;
            l[0] as usize
        }
        other => bail!("bad reply atyp {other:#x}"),
    };
    let mut skip = vec![0u8; addr_len + 2];
    stream
        .read_exact(&mut skip)
        .await
        .context("socks client reply addr")?;
    Ok(())
}

/// Shared probe state tracking whether the loopback tunnel's upstream dial over
/// the mesh (`socks5_client_connect` or direct overlay TCP) has connected, or
/// failed before reaching the remote RDP port.
#[derive(Debug, Default, Clone)]
pub struct RdpLoopbackTunnelProbe {
    inner: Arc<RdpLoopbackTunnelProbeInner>,
}

#[derive(Debug, Default)]
struct RdpLoopbackTunnelProbeInner {
    upstream_connected: AtomicBool,
    last_upstream_error: std::sync::Mutex<Option<String>>,
}

impl RdpLoopbackTunnelProbe {
    pub fn upstream_connected(&self) -> bool {
        self.inner.upstream_connected.load(Ordering::Acquire)
    }

    pub fn last_upstream_error(&self) -> Option<String> {
        self.inner
            .last_upstream_error
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }

    fn mark_connected(&self) {
        self.inner.upstream_connected.store(true, Ordering::Release);
    }

    fn record_error(&self, err: impl Into<String>) {
        let mut slot = self
            .inner
            .last_upstream_error
            .lock()
            .unwrap_or_else(|p| p.into_inner());
        *slot = Some(err.into());
    }
}

/// Spawn the background local loopback TCP forwarding pump together with an
/// [`RdpLoopbackTunnelProbe`] so the pre-`mstsc` check can distinguish an
/// unreachable mesh/RDP endpoint from a post-TCP X.224/TLS stall.
pub fn spawn_rdp_loopback_tunnel_with_probe(
    listener: tokio::net::TcpListener,
    dial_ip: String,
    forward_port: u16,
    socks_port: Option<u16>,
) -> (tokio::task::JoinHandle<()>, RdpLoopbackTunnelProbe) {
    let probe = RdpLoopbackTunnelProbe::default();
    let task_probe = probe.clone();
    let handle = tokio::spawn(async move {
        while let Ok((mut tcp, _)) = listener.accept().await {
            let h = dial_ip.clone();
            let conn_probe = task_probe.clone();
            tokio::spawn(async move {
                let upstream_res = match socks_port {
                    Some(sp) => {
                        match tokio::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, sp))
                            .await
                        {
                            Ok(mut s) => socks5_client_connect(&mut s, &h, forward_port)
                                .await
                                .map(|()| s)
                                .map_err(|e| std::io::Error::other(e.to_string())),
                            Err(e) => Err(e),
                        }
                    }
                    None => tokio::net::TcpStream::connect((h.as_str(), forward_port)).await,
                };
                match upstream_res {
                    Ok(mut remote) => {
                        conn_probe.mark_connected();
                        let _ = tcp.set_nodelay(true);
                        let _ = remote.set_nodelay(true);
                        let _ = tokio::io::copy_bidirectional(&mut tcp, &mut remote).await;
                    }
                    Err(e) => {
                        conn_probe.record_error(e.to_string());
                        let _ = tcp.shutdown().await;
                    }
                }
            });
        }
    });
    (handle, probe)
}

/// Spawn the background local loopback TCP forwarding pump that bridges
/// accepted connections on `listener` (`127.77.x.y:<port>`) to `dial_ip:forward_port`
/// either via the daemon's loopback SOCKS5 proxy (`socks_port == Some(sp)`,
/// unprivileged netstack mode) or directly over the OS overlay TUN interface.
pub fn spawn_rdp_loopback_tunnel(
    listener: tokio::net::TcpListener,
    dial_ip: String,
    forward_port: u16,
    socks_port: Option<u16>,
) -> tokio::task::JoinHandle<()> {
    spawn_rdp_loopback_tunnel_with_probe(listener, dial_ip, forward_port, socks_port).0
}

/// Distinct fail-closed error classes for the pre-`mstsc` RDP tunnel check
/// (`V0028 §4.4` + `V0029 §3.1`).
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RdpPrecheckError {
    #[error("经网格无法连到目标 RDP 端口 ({target}:{port})：{detail}")]
    Unreachable {
        target: String,
        port: u16,
        detail: String,
    },
    #[error("目标 RDP 拒绝 TLS 升级或尝试降级为明文 RDP ({target}:{port})：{detail}")]
    ProtocolDowngrade {
        target: String,
        port: u16,
        detail: String,
    },
    #[error(
        "目标 RDP TLS 握手失败（协议版本低于 TLS 1.2 或证书签名无效）({target}:{port})：{detail}"
    )]
    TlsInvalid {
        target: String,
        port: u16,
        detail: String,
    },
    #[error("目标 RDP 证书 SHA-256 指纹不匹配 ({target}:{port})：期望 {expected}，实际 {actual}")]
    FingerprintMismatch {
        target: String,
        port: u16,
        expected: String,
        actual: String,
    },
    #[error("目标 RDP 握手预检超时（阶段：{stage}）({target}:{port})")]
    Timeout {
        target: String,
        port: u16,
        stage: &'static str,
    },
}

/// Verified outcome of a pre-`mstsc` RDP tunnel pre-check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RdpPrecheckOutcome {
    /// Selected `[MS-BCGR]` negotiation protocol (`0x01` SSL, `0x02` Hybrid/NLA,
    /// `0x08` HybridEx, or `0x00` classic RDP in unpinned reachability-only mode).
    pub selected_protocol: u32,
    /// Lowercase colon-separated SHA-256 of the presented TLS leaf certificate
    /// DER when a TLS handshake was performed.
    pub leaf_cert_sha256: Option<String>,
    /// `true` iff `leaf_cert_sha256` was matched against a non-empty pinned
    /// SHA-256 fingerprint.
    pub pinned_verified: bool,
}

const X224_PROTOCOL_RDP: u32 = 0x0000_0000;
const X224_PROTOCOL_SSL: u32 = 0x0000_0001;
const X224_PROTOCOL_HYBRID: u32 = 0x0000_0002;
const X224_PROTOCOL_HYBRID_EX: u32 = 0x0000_0008;

/// `[MS-BCGR] §2.2.1.1` 19-byte TPKT + X.224 Connection Request PDU carrying
/// `RDP_NEG_REQ` for `PROTOCOL_SSL | PROTOCOL_HYBRID` (`0x0000_0003` LE).
/// Requesting both `SSL` and `HYBRID` allows Windows NLA (`TermService`, which
/// requires `HYBRID` by default) and `xrdp` (`SSL` or `HYBRID`) to proceed
/// directly into the TLS 1.2/1.3 handshake.
const X224_TLS_CONNECTION_REQUEST: [u8; 19] = [
    0x03, 0x00, 0x00, 0x13, // TPKT v3, reserved=0, length=19 (BE)
    0x0e, // X.224 LI = 14 bytes following
    0xe0, // X.224 CR (0xE0)
    0x00, 0x00, // DST-REF
    0x00, 0x00, // SRC-REF
    0x00, // Class 0
    0x01, // TYPE_RDP_NEG_REQ
    0x00, // flags
    0x08, 0x00, // length = 8 (LE)
    0x03, 0x00, 0x00, 0x00, // PROTOCOL_SSL | PROTOCOL_HYBRID (LE)
];

fn format_sha256_colon_hex(der: &[u8]) -> String {
    let digest = Sha256::digest(der);
    digest
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

#[derive(Debug)]
struct RdpLeafCaptureVerifier {
    provider: Arc<CryptoProvider>,
    observed_leaf_sha256: std::sync::Mutex<Option<String>>,
}

impl RdpLeafCaptureVerifier {
    fn new(provider: Arc<CryptoProvider>) -> Self {
        Self {
            provider,
            observed_leaf_sha256: std::sync::Mutex::new(None),
        }
    }

    fn observed(&self) -> Option<String> {
        self.observed_leaf_sha256
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone()
    }
}

impl ServerCertVerifier for RdpLeafCaptureVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        if end_entity.as_ref().is_empty() {
            return Err(rustls::Error::General(
                "server presented empty leaf certificate".into(),
            ));
        }
        let fp = format_sha256_colon_hex(end_entity.as_ref());
        *self
            .observed_leaf_sha256
            .lock()
            .unwrap_or_else(|p| p.into_inner()) = Some(fp);
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum X224ConfirmResult {
    SelectedProtocol(u32),
    NegFailure(u32),
}

async fn exchange_x224_connection_request(
    tcp: &mut tokio::net::TcpStream,
    probe: &RdpLoopbackTunnelProbe,
    target_label: &str,
    remote_port: u16,
) -> std::result::Result<X224ConfirmResult, RdpPrecheckError> {
    let map_io = |err: std::io::Error| -> RdpPrecheckError {
        if !probe.upstream_connected() {
            let detail = probe
                .last_upstream_error()
                .unwrap_or_else(|| err.to_string());
            RdpPrecheckError::Unreachable {
                target: target_label.to_string(),
                port: remote_port,
                detail,
            }
        } else {
            RdpPrecheckError::ProtocolDowngrade {
                target: target_label.to_string(),
                port: remote_port,
                detail: format!("X.224 握手读取失败：{err}"),
            }
        }
    };

    tcp.write_all(&X224_TLS_CONNECTION_REQUEST)
        .await
        .map_err(map_io)?;
    tcp.flush().await.map_err(map_io)?;

    let mut tpkt = [0u8; 4];
    tcp.read_exact(&mut tpkt).await.map_err(map_io)?;
    if tpkt[0] != 0x03 {
        return Err(RdpPrecheckError::ProtocolDowngrade {
            target: target_label.to_string(),
            port: remote_port,
            detail: format!("非 TPKT v3 响应头 ({:#04x})", tpkt[0]),
        });
    }
    let tpkt_len = u16::from_be_bytes([tpkt[2], tpkt[3]]) as usize;
    if !(11..=1024).contains(&tpkt_len) {
        return Err(RdpPrecheckError::ProtocolDowngrade {
            target: target_label.to_string(),
            port: remote_port,
            detail: format!("非法 TPKT 长度 ({tpkt_len})"),
        });
    }
    let mut body = vec![0u8; tpkt_len - 4];
    tcp.read_exact(&mut body).await.map_err(map_io)?;
    let li = body[0] as usize;
    if li < 6 || 1 + li > body.len() {
        return Err(RdpPrecheckError::ProtocolDowngrade {
            target: target_label.to_string(),
            port: remote_port,
            detail: format!("非法 X.224 LI 长度 ({li})"),
        });
    }
    let pdu_type = body[1] & 0xf0;
    if pdu_type != 0xd0 {
        return Err(RdpPrecheckError::ProtocolDowngrade {
            target: target_label.to_string(),
            port: remote_port,
            detail: format!(
                "期望 X.224 Connection Confirm (0xD0)，收到 {:#04x}",
                body[1]
            ),
        });
    }
    if body.len() < 15 {
        return Ok(X224ConfirmResult::SelectedProtocol(X224_PROTOCOL_RDP));
    }
    let neg_type = body[7];
    let neg_len = u16::from_le_bytes([body[9], body[10]]);
    if neg_len < 8 {
        return Err(RdpPrecheckError::ProtocolDowngrade {
            target: target_label.to_string(),
            port: remote_port,
            detail: format!("非法 RDP_NEG 长度 ({neg_len})"),
        });
    }
    let code = u32::from_le_bytes([body[11], body[12], body[13], body[14]]);
    match neg_type {
        0x02 => Ok(X224ConfirmResult::SelectedProtocol(code)),
        0x03 => Ok(X224ConfirmResult::NegFailure(code)),
        other => Err(RdpPrecheckError::ProtocolDowngrade {
            target: target_label.to_string(),
            port: remote_port,
            detail: format!("未知 RDP_NEG 类型 ({other:#04x})"),
        }),
    }
}

/// Perform the pre-`mstsc` X.224 + TLS 1.2/1.3 handshake and leaf-certificate
/// SHA-256 verification over `local_tunnel_addr` within `timeout_budget`.
///
/// Security & timing model (`V0028 §4.3`):
/// - The pre-check connection and `mstsc.exe`'s subsequent connection are two
///   separate TCP streams on `127.77.x.y:<port>`, but both traverse the exact
///   same WireGuard-authenticated overlay peer (`dial_ip:remote_port`).
/// - The SHA-256 fingerprint comparison proves the identity of the TLS endpoint
///   answering on that WireGuard-authenticated peer at the moment of the pre-check.
/// - Under TLS 1.3 (RFC 8446), the server `Certificate` message is encrypted
///   after `ServerHello`, so the local TCP forwarder cannot passively inspect
///   the certificate inside `mstsc.exe`'s own TLS connection in transit; we
///   therefore accept this bounded pre-check-to-`mstsc` window.
pub async fn precheck_rdp_tunnel_tls_with_timeout(
    local_tunnel_addr: SocketAddr,
    probe: &RdpLoopbackTunnelProbe,
    target_label: &str,
    remote_port: u16,
    expected_cert_sha256: Option<&str>,
    timeout_budget: Duration,
) -> std::result::Result<RdpPrecheckOutcome, RdpPrecheckError> {
    let normalized_expected =
        match expected_cert_sha256 {
            Some(raw) if !raw.trim().is_empty() => Some(normalize_cert_sha256(raw).map_err(
                |e| RdpPrecheckError::TlsInvalid {
                    target: target_label.to_string(),
                    port: remote_port,
                    detail: e.to_string(),
                },
            )?),
            _ => None,
        };

    let stage_cell = std::sync::Mutex::new("连接网格与 X.224 协商");
    let fut = async {
        let mut tcp = tokio::net::TcpStream::connect(local_tunnel_addr)
            .await
            .map_err(|e| RdpPrecheckError::Unreachable {
                target: target_label.to_string(),
                port: remote_port,
                detail: format!("本地回环隧道连接失败：{e}"),
            })?;
        let _ = tcp.set_nodelay(true);

        let selected_protocol =
            match exchange_x224_connection_request(&mut tcp, probe, target_label, remote_port)
                .await?
            {
                X224ConfirmResult::SelectedProtocol(p)
                    if p == X224_PROTOCOL_SSL
                        || p == X224_PROTOCOL_HYBRID
                        || p == X224_PROTOCOL_HYBRID_EX =>
                {
                    p
                }
                X224ConfirmResult::SelectedProtocol(X224_PROTOCOL_RDP) => {
                    return Err(RdpPrecheckError::ProtocolDowngrade {
                        target: target_label.to_string(),
                        port: remote_port,
                        detail: "对端仅选择明文 PROTOCOL_RDP (0x00)，未启用 TLS".to_string(),
                    });
                }
                X224ConfirmResult::SelectedProtocol(other) => {
                    return Err(RdpPrecheckError::ProtocolDowngrade {
                        target: target_label.to_string(),
                        port: remote_port,
                        detail: format!("对端返回不支持的协议标志 {other:#x}"),
                    });
                }
                X224ConfirmResult::NegFailure(code) => {
                    return Err(RdpPrecheckError::ProtocolDowngrade {
                        target: target_label.to_string(),
                        port: remote_port,
                        detail: format!("对端返回 RDP_NEG_FAILURE (code={code:#x})"),
                    });
                }
            };

        *stage_cell.lock().unwrap_or_else(|p| p.into_inner()) = "TLS 1.2/1.3 证书握手";

        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let verifier = Arc::new(RdpLeafCaptureVerifier::new(Arc::clone(&provider)));
        let tls_cfg = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .map_err(|e| RdpPrecheckError::TlsInvalid {
                target: target_label.to_string(),
                port: remote_port,
                detail: e.to_string(),
            })?
            .dangerous()
            .with_custom_certificate_verifier(verifier.clone())
            .with_no_client_auth();

        let connector = tokio_rustls::TlsConnector::from(Arc::new(tls_cfg));
        let server_name =
            ServerName::try_from("rdp.meshharbor.internal").expect("static valid DNS name for SNI");
        let mut tls_stream = connector.connect(server_name, tcp).await.map_err(|e| {
            RdpPrecheckError::TlsInvalid {
                target: target_label.to_string(),
                port: remote_port,
                detail: e.to_string(),
            }
        })?;

        let actual_fp = tls_stream
            .get_ref()
            .1
            .peer_certificates()
            .and_then(|certs| certs.first())
            .map(|c| format_sha256_colon_hex(c.as_ref()))
            .or_else(|| verifier.observed())
            .ok_or_else(|| RdpPrecheckError::TlsInvalid {
                target: target_label.to_string(),
                port: remote_port,
                detail: "对端未提供任何 X.509 叶子证书".to_string(),
            })?;

        let _ = tls_stream.shutdown().await;

        let pinned_verified = if let Some(expected) = normalized_expected {
            if actual_fp != expected {
                return Err(RdpPrecheckError::FingerprintMismatch {
                    target: target_label.to_string(),
                    port: remote_port,
                    expected,
                    actual: actual_fp,
                });
            }
            true
        } else {
            false
        };

        Ok(RdpPrecheckOutcome {
            selected_protocol,
            leaf_cert_sha256: Some(actual_fp),
            pinned_verified,
        })
    };

    match tokio::time::timeout(timeout_budget, fut).await {
        Ok(res) => res,
        Err(_) => {
            if !probe.upstream_connected() {
                let detail = probe.last_upstream_error().unwrap_or_else(|| {
                    format!(
                        "{} 秒内未建立网格连接（被控端可能已离线或端口未开放）",
                        timeout_budget.as_secs().max(1)
                    )
                });
                Err(RdpPrecheckError::Unreachable {
                    target: target_label.to_string(),
                    port: remote_port,
                    detail,
                })
            } else {
                let stage = *stage_cell.lock().unwrap_or_else(|p| p.into_inner());
                Err(RdpPrecheckError::Timeout {
                    target: target_label.to_string(),
                    port: remote_port,
                    stage,
                })
            }
        }
    }
}

/// Perform the pre-`mstsc` X.224 + TLS 1.2/1.3 certificate check using the
/// default 5-second budget ([`RDP_PRECHECK_TIMEOUT`]).
pub async fn precheck_rdp_tunnel_tls(
    local_tunnel_addr: SocketAddr,
    probe: &RdpLoopbackTunnelProbe,
    target_label: &str,
    remote_port: u16,
    expected_cert_sha256: Option<&str>,
) -> std::result::Result<RdpPrecheckOutcome, RdpPrecheckError> {
    precheck_rdp_tunnel_tls_with_timeout(
        local_tunnel_addr,
        probe,
        target_label,
        remote_port,
        expected_cert_sha256,
        RDP_PRECHECK_TIMEOUT,
    )
    .await
}

/// Reachability pre-check used when `pinned_cert_sha256 == None` in normal
/// (non-`--check`) sessions (`V0028 §2` + `V0029 §3.1`): verifies within 5 s
/// that the remote RDP port answers an X.224 Connection Request over the mesh
/// (failing fast with `"经网格无法连到目标 RDP 端口 ..."` when the target daemon
/// is stopped) while allowing `mstsc.exe` to apply its native trust-store check.
pub async fn precheck_rdp_tunnel_reachability_with_timeout(
    local_tunnel_addr: SocketAddr,
    probe: &RdpLoopbackTunnelProbe,
    target_label: &str,
    remote_port: u16,
    timeout_budget: Duration,
) -> std::result::Result<RdpPrecheckOutcome, RdpPrecheckError> {
    let fut = async {
        let mut tcp = tokio::net::TcpStream::connect(local_tunnel_addr)
            .await
            .map_err(|e| RdpPrecheckError::Unreachable {
                target: target_label.to_string(),
                port: remote_port,
                detail: format!("本地回环隧道连接失败：{e}"),
            })?;
        let _ = tcp.set_nodelay(true);
        let confirm =
            exchange_x224_connection_request(&mut tcp, probe, target_label, remote_port).await?;
        let _ = tcp.shutdown().await;
        let selected_protocol = match confirm {
            X224ConfirmResult::SelectedProtocol(p) => p,
            X224ConfirmResult::NegFailure(_) => X224_PROTOCOL_RDP,
        };
        Ok(RdpPrecheckOutcome {
            selected_protocol,
            leaf_cert_sha256: None,
            pinned_verified: false,
        })
    };

    match tokio::time::timeout(timeout_budget, fut).await {
        Ok(res) => res,
        Err(_) => {
            if !probe.upstream_connected() {
                let detail = probe.last_upstream_error().unwrap_or_else(|| {
                    format!(
                        "{} 秒内未建立网格连接（被控端可能已离线或端口未开放）",
                        timeout_budget.as_secs().max(1)
                    )
                });
                Err(RdpPrecheckError::Unreachable {
                    target: target_label.to_string(),
                    port: remote_port,
                    detail,
                })
            } else {
                Err(RdpPrecheckError::Timeout {
                    target: target_label.to_string(),
                    port: remote_port,
                    stage: "X.224 可达性预检",
                })
            }
        }
    }
}

/// Reachability pre-check with the default 5-second budget ([`RDP_PRECHECK_TIMEOUT`]).
pub async fn precheck_rdp_tunnel_reachability(
    local_tunnel_addr: SocketAddr,
    probe: &RdpLoopbackTunnelProbe,
    target_label: &str,
    remote_port: u16,
) -> std::result::Result<RdpPrecheckOutcome, RdpPrecheckError> {
    precheck_rdp_tunnel_reachability_with_timeout(
        local_tunnel_addr,
        probe,
        target_label,
        remote_port,
        RDP_PRECHECK_TIMEOUT,
    )
    .await
}

/// Spawn the planned native RDP client process and deliver `stdin_payload`
/// (if present) over an anonymous `stdin` pipe so secrets never touch `argv`,
/// `env`, or disk.
pub fn spawn_planned_rdp_client(plan: &PlannedRdpInvocation) -> Result<Child> {
    let mut cmd = Command::new(&plan.program);
    cmd.args(&plan.args).envs(&plan.env);
    if plan.stdin_payload.is_some() {
        cmd.stdin(Stdio::piped());
    }
    let mut child = cmd
        .spawn()
        .with_context(|| format!("failed to launch native RDP client '{}'", plan.program))?;
    if let (Some(payload), Some(mut child_stdin)) =
        (plan.stdin_payload.as_ref(), child.stdin.take())
    {
        child_stdin
            .write_all(format!("{payload}\n").as_bytes())
            .context("failed passing RDP credential to client stdin")?;
    }
    Ok(child)
}

/// Resolve the FreeRDP client binary from a given `PATH` (`xfreerdp3`
/// preferred, falling back to `xfreerdp` or `wlfreerdp`).
pub fn resolve_freerdp_program_in_path(path_env: Option<&std::ffi::OsStr>) -> String {
    if let Some(path_os) = path_env {
        for candidate in ["xfreerdp3", "xfreerdp", "wlfreerdp"] {
            for dir in std::env::split_paths(path_os) {
                let full = dir.join(candidate);
                if full.is_file() {
                    return candidate.to_string();
                }
            }
        }
    }
    "xfreerdp3".to_string()
}

/// Resolve the FreeRDP client binary on Linux/macOS (`MESHHARBOR_FREERDP_BIN`
/// override, else `xfreerdp3` -> `xfreerdp` -> `wlfreerdp` in `PATH`).
pub fn resolve_freerdp_program() -> String {
    if let Ok(custom) = std::env::var("MESHHARBOR_FREERDP_BIN") {
        let trimmed = custom.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
    }
    resolve_freerdp_program_in_path(std::env::var_os("PATH").as_deref())
}

/// Extract the `attribute.username` value from `secret-tool search` output,
/// failing closed if missing or empty.
pub fn parse_linux_secret_tool_username(search_output: &str) -> Result<String> {
    for line in search_output.lines() {
        if let Some(rest) = line.trim().strip_prefix("attribute.username = ") {
            let user = rest.trim();
            if !user.is_empty() {
                return Ok(user.to_string());
            }
        }
    }
    bail!(
        "stored RDP credential in secret-tool is missing a non-empty 'username' attribute; refusing fallback username"
    )
}

/// Abstract client-local OS secure credential store seam.
pub trait RdpCredentialStore: Send + Sync {
    fn save(&self, scope: &RdpCredentialScope, cred: &StoredRdpCredential) -> Result<()>;
    fn load(&self, scope: &RdpCredentialScope) -> Result<Option<StoredRdpCredential>>;
    fn delete(&self, scope: &RdpCredentialScope) -> Result<bool>;
}

/// Planned native RDP client process invocation.
/// `stdin_payload` is redacted in `Debug` so secrets can never leak to logs.
#[derive(Clone, PartialEq, Eq)]
pub struct PlannedRdpInvocation {
    pub program: String,
    pub args: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub stdin_payload: Option<String>,
    pub windows_session_target: Option<String>,
    pub pinned_cert_sha256: Option<String>,
    pub local_tunnel_addr: SocketAddr,
}

impl std::fmt::Debug for PlannedRdpInvocation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PlannedRdpInvocation")
            .field("program", &self.program)
            .field("args", &self.args)
            .field("env", &self.env)
            .field(
                "stdin_payload",
                &self.stdin_payload.as_ref().map(|_| "<redacted>"),
            )
            .field("windows_session_target", &self.windows_session_target)
            .field("pinned_cert_sha256", &self.pinned_cert_sha256)
            .field("local_tunnel_addr", &self.local_tunnel_addr)
            .finish()
    }
}

/// Parse `<user>@<device>` or `<device>`.
pub fn parse_user_and_device(raw: &str) -> Result<(Option<String>, String)> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        bail!("target device must not be empty");
    }
    if let Some((user, host)) = trimmed.rsplit_once('@') {
        let user = user.trim();
        let host = host.trim();
        if user.is_empty() {
            bail!("empty username before '@' in target '{trimmed}'");
        }
        if host.is_empty() {
            bail!("empty device name after '@' in target '{trimmed}'");
        }
        Ok((Some(user.to_string()), host.to_string()))
    } else {
        Ok((None, trimmed.to_string()))
    }
}

/// Validate extra arguments forwarded to the native RDP client.
/// Rejects any flag that carries a password on the command line or weakens
/// TLS certificate verification.
pub fn validate_extra_client_args(args: &[String]) -> Result<()> {
    for raw in args {
        let lower = raw.trim().to_ascii_lowercase();
        if lower == "cmdkey"
            || lower == "cmdkey.exe"
            || lower.starts_with("/pass:")
            || lower.starts_with("/pass=")
            || lower == "/pass"
        {
            bail!(
                "refusing unsafe argument '{raw}': `cmdkey /pass:` leaks secrets into process argv"
            );
        }
        if lower.starts_with("/p:")
            || lower.starts_with("/p=")
            || lower == "/p"
            || lower.starts_with("/password")
            || lower == "-p"
            || lower == "--password"
            || lower.starts_with("--password=")
        {
            bail!(
                "refusing plaintext password flag '{raw}': RDP passwords must never be passed in argv"
            );
        }
        if lower == "/cert:ignore"
            || lower == "/cert-ignore"
            || lower == "--ignore-certificate"
            || lower == "--ignore-cert"
            || lower == "--insecure"
            || lower == "/insecure"
            || lower == "--skip-cert-check"
            || lower == "--no-verify-cert"
            || lower == "/cert:tofu"
            || lower == "/cert-tofu"
        {
            bail!("refusing '{raw}': disabling RDP certificate verification is not permitted");
        }
    }
    Ok(())
}

/// Normalize a SHA-256 certificate fingerprint (`AA:BB:...` or 64 hex chars)
/// into lowercase colon-separated `aa:bb:...` format.
pub fn normalize_cert_sha256(raw: &str) -> Result<String> {
    let hex_only: String = raw
        .trim()
        .chars()
        .filter(|c| *c != ':' && *c != '-')
        .collect();
    if hex_only.len() != 64 || !hex_only.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!(
            "invalid RDP certificate SHA-256 fingerprint '{raw}': expected 64 hex digits (or 32 colon-separated hex bytes)"
        );
    }
    let lower = hex_only.to_ascii_lowercase();
    let pairs: Vec<&str> = (0..32).map(|i| &lower[i * 2..i * 2 + 2]).collect();
    Ok(pairs.join(":"))
}

pub fn is_kill_switch_enabled(cli_no_saved: bool, env_val: Option<&str>) -> bool {
    if cli_no_saved {
        return true;
    }
    matches!(
        env_val.map(|v| v.trim().to_ascii_lowercase()).as_deref(),
        Some("1" | "true" | "yes" | "on")
    )
}

/// Build the Linux `secret-tool store` invocation plan.
/// The password is written exclusively to `stdin`, never `argv`.
pub fn build_linux_secret_tool_store_plan(
    scope: &RdpCredentialScope,
    cred: &StoredRdpCredential,
) -> Result<(String, Vec<String>, String)> {
    if scope.org_id.trim().is_empty() || scope.device_id.trim().is_empty() {
        bail!("credential scope org_id and device_id must not be empty");
    }
    let qualified = cred.qualified_username();
    if qualified.trim().is_empty() {
        bail!("RDP username must not be empty");
    }
    let label = format!("MeshHarbor RDP ({})", scope.store_target_name());
    let args = vec![
        "store".to_string(),
        format!("--label={label}"),
        "service".to_string(),
        "meshharbor-rdp".to_string(),
        "org".to_string(),
        scope.org_id.clone(),
        "device".to_string(),
        scope.device_id.clone(),
        "username".to_string(),
        qualified,
    ];
    let stdin_payload = format!("{}\n", cred.password());
    Ok(("secret-tool".to_string(), args, stdin_payload))
}

/// Build the macOS `/usr/bin/security -i` (interactive stdin) invocation plan.
/// Passing `-i` reads the `add-generic-password` command from `stdin` so `-w`
/// never appears in the process `argv` table (`ps`).
pub fn build_macos_security_store_plan(
    scope: &RdpCredentialScope,
    cred: &StoredRdpCredential,
) -> Result<(String, Vec<String>, String)> {
    if scope.org_id.trim().is_empty() || scope.device_id.trim().is_empty() {
        bail!("credential scope org_id and device_id must not be empty");
    }
    let qualified = cred.qualified_username();
    if qualified.trim().is_empty() {
        bail!("RDP username must not be empty");
    }
    if cred.password().contains('\n')
        || cred.password().contains('\r')
        || cred.password().contains('\0')
    {
        bail!("RDP password must not contain control newline/NUL characters");
    }
    let service = scope.store_target_name();
    let esc = |s: &str| s.replace('\\', "\\\\").replace('"', "\\\"");
    let stdin_cmd = format!(
        "add-generic-password -U -a \"{}\" -s \"{}\" -w \"{}\"\n",
        esc(&qualified),
        esc(&service),
        esc(cred.password())
    );
    Ok((
        "/usr/bin/security".to_string(),
        vec!["-i".to_string()],
        stdin_cmd,
    ))
}

/// Compute the effective remote RDP TCP port using precedence:
/// `(1) explicit CLI/bridge port -> (2) device.rdp_port -> (3) opts.port / 3389`.
pub fn effective_rdp_port(opts: &RdpCliOptions, device: &ResolvedRdpDevice) -> u16 {
    opts.explicit_port
        .filter(|&p| p > 0)
        .or_else(|| device.rdp_port.filter(|&p| p > 0))
        .unwrap_or(if opts.port > 0 { opts.port } else { 3389 })
}

/// Compute the normalized pinned SHA-256 certificate fingerprint using precedence:
/// `(1) explicit opts.cert_sha256 -> (2) device.rdp_cert_sha256 -> (3) None`.
pub fn effective_pinned_cert_sha256(
    opts: &RdpCliOptions,
    device: &ResolvedRdpDevice,
) -> Result<Option<String>> {
    if let Some(raw) = opts
        .cert_sha256
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        return Ok(Some(normalize_cert_sha256(raw)?));
    }
    if let Some(raw) = device
        .rdp_cert_sha256
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        return Ok(Some(normalize_cert_sha256(raw)?));
    }
    Ok(None)
}

/// Pure session planner that enforces all X17 + V0028 security invariants:
/// - Default OFF (neither reads nor writes `store` unless explicitly opted in).
/// - Kill switch (`--no-saved-credentials` or `MESHHARBOR_RDP_PASSWORDLESS_DISABLED=1`).
/// - `--clear-credentials` deletes from `store` and returns `Ok(None)`.
/// - Rejects non-loopback tunnel addresses and forbidden extra arguments.
/// - Pins target TLS certificate SHA-256 fingerprint when available (enforced via
///   [`precheck_rdp_tunnel_tls`] prior to launching `mstsc.exe` on Windows, and
///   additionally via `/cert:fingerprint:sha256:<fp>` on FreeRDP).
pub fn plan_rdp_session(
    opts: &RdpCliOptions,
    device: &ResolvedRdpDevice,
    local_tunnel_addr: SocketAddr,
    store: &dyn RdpCredentialStore,
    password_prompt: Option<&str>,
    kill_switch_env_val: Option<&str>,
    platform: &str,
) -> Result<Option<PlannedRdpInvocation>> {
    validate_extra_client_args(&opts.extra_args)?;
    let port_to_check = opts.explicit_port.unwrap_or(opts.port);
    if port_to_check == 0 {
        bail!("remote RDP port must be between 1 and 65535");
    }
    if !local_tunnel_addr.ip().is_loopback() {
        bail!(
            "local RDP tunnel address {} must be a loopback address (127.0.0.1 or ::1)",
            local_tunnel_addr
        );
    }

    let (target_user, _target_host) = parse_user_and_device(&opts.target)?;
    let scope = RdpCredentialScope {
        org_id: device.org_id.clone(),
        device_id: device.device_id.clone(),
    };

    if opts.clear_credentials {
        let _ = store.delete(&scope)?;
        return Ok(None);
    }

    if is_kill_switch_enabled(opts.no_saved_credentials, kill_switch_env_val)
        && (opts.save_credentials || opts.use_saved_credentials)
    {
        bail!(
            "saved RDP credentials are disabled by kill switch (--no-saved-credentials or {}=1)",
            KILL_SWITCH_ENV
        );
    }

    let explicit_user = opts
        .user
        .as_deref()
        .map(str::trim)
        .filter(|u| !u.is_empty())
        .map(ToOwned::to_owned)
        .or(target_user);

    let explicit_domain = opts
        .domain
        .as_deref()
        .map(str::trim)
        .filter(|d| !d.is_empty())
        .map(ToOwned::to_owned);

    let pinned_cert_sha256 = effective_pinned_cert_sha256(opts, device)?;
    let platform_norm = platform.trim().to_ascii_lowercase();

    let mut active_cred: Option<StoredRdpCredential> = None;

    if opts.save_credentials {
        let user = explicit_user.clone().context(
            "--save-credentials requires an RDP username (via `--user <name>` or `<user>@<device>`)",
        )?;
        let pw = password_prompt
            .filter(|p| !p.is_empty())
            .context("--save-credentials requires a non-empty RDP password from stdin/prompt")?;
        let cred = StoredRdpCredential::new(user, explicit_domain.clone(), pw);
        store.save(&scope, &cred)?;
        if opts.use_saved_credentials {
            active_cred = Some(cred);
        }
    }

    if opts.use_saved_credentials && active_cred.is_none() {
        let loaded = store.load(&scope)?.with_context(|| {
            format!(
                "no saved RDP credential found in local OS store for device '{}' ({}); run once with --save-credentials first",
                device.device_name,
                scope.store_target_name()
            )
        })?;
        active_cred = Some(loaded);
    }

    let effective_user = active_cred
        .as_ref()
        .map(|c| c.username.clone())
        .or(explicit_user);
    let effective_domain = active_cred
        .as_ref()
        .and_then(|c| c.domain.clone())
        .or(explicit_domain);

    let dial_endpoint = format!("{}:{}", local_tunnel_addr.ip(), local_tunnel_addr.port());

    if platform_norm == "windows" {
        let mut args = vec![format!("/v:{dial_endpoint}")];
        args.extend(opts.extra_args.iter().cloned());
        let windows_session_target = if active_cred.is_some() {
            if local_tunnel_addr.ip() == std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)
                || local_tunnel_addr.ip() == std::net::IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)
            {
                bail!(
                    "refusing shared loopback address {} for Windows TERMSRV credential target; allocate a unique per-session 127.77.x.y loopback IP",
                    local_tunnel_addr.ip()
                );
            }
            Some(format!("TERMSRV/{}", local_tunnel_addr.ip()))
        } else {
            None
        };
        Ok(Some(PlannedRdpInvocation {
            program: "mstsc.exe".to_string(),
            args,
            env: BTreeMap::new(),
            stdin_payload: None,
            windows_session_target,
            pinned_cert_sha256,
            local_tunnel_addr,
        }))
    } else {
        let mut args = vec![format!("/v:{dial_endpoint}")];
        if let Some(u) = &effective_user {
            args.push(format!("/u:{u}"));
        }
        if let Some(d) = &effective_domain {
            args.push(format!("/d:{d}"));
        }
        if let Some(fp) = &pinned_cert_sha256 {
            args.push(format!("/cert:fingerprint:sha256:{fp}"));
        }
        let stdin_payload = if let Some(cred) = &active_cred {
            args.push("/from-stdin:force".to_string());
            Some(cred.password().to_string())
        } else {
            None
        };
        args.extend(opts.extra_args.iter().cloned());
        Ok(Some(PlannedRdpInvocation {
            program: resolve_freerdp_program(),
            args,
            env: BTreeMap::new(),
            stdin_payload,
            windows_session_target: None,
            pinned_cert_sha256,
            local_tunnel_addr,
        }))
    }
}

/// Real OS secure credential store implementation.
#[derive(Debug, Default, Clone, Copy)]
pub struct OsRdpCredentialStore;

impl RdpCredentialStore for OsRdpCredentialStore {
    fn save(&self, scope: &RdpCredentialScope, cred: &StoredRdpCredential) -> Result<()> {
        os_store::save(scope, cred)
    }

    fn load(&self, scope: &RdpCredentialScope) -> Result<Option<StoredRdpCredential>> {
        os_store::load(scope)
    }

    fn delete(&self, scope: &RdpCredentialScope) -> Result<bool> {
        os_store::delete(scope)
    }
}

/// Ephemeral session-scoped `CRED_TYPE_DOMAIN_PASSWORD` entry in Windows
/// Credential Manager (`TERMSRV/127.77.x.y`) that is automatically removed on drop.
#[derive(Debug)]
pub struct WindowsSessionTargetGuard {
    target: String,
}

impl WindowsSessionTargetGuard {
    pub fn install(target: &str, cred: &StoredRdpCredential) -> Result<Self> {
        os_store::install_windows_session_target(target, cred)?;
        Ok(Self {
            target: target.to_string(),
        })
    }

    pub fn exists(target: &str) -> Result<bool> {
        os_store::windows_session_target_exists(target)
    }

    pub fn read(target: &str) -> Result<Option<StoredRdpCredential>> {
        os_store::read_windows_session_target(target)
    }
}

impl Drop for WindowsSessionTargetGuard {
    fn drop(&mut self) {
        let _ = os_store::remove_windows_session_target(&self.target);
    }
}

#[cfg(windows)]
mod os_store {
    use super::{RdpCredentialScope, StoredRdpCredential};
    use anyhow::{Result, bail};
    use core::ffi::c_void;
    use std::os::windows::ffi::{OsStrExt, OsStringExt};

    const CRED_TYPE_GENERIC: u32 = 1;
    const CRED_TYPE_DOMAIN_PASSWORD: u32 = 2;
    const CRED_PERSIST_SESSION: u32 = 1;
    const CRED_PERSIST_LOCAL_MACHINE: u32 = 2;
    const ERROR_NOT_FOUND: u32 = 1168;

    #[repr(C)]
    #[derive(Copy, Clone, Default)]
    struct FileTime {
        dw_low_date_time: u32,
        dw_high_date_time: u32,
    }

    #[repr(C)]
    struct CredentialW {
        flags: u32,
        cred_type: u32,
        target_name: *mut u16,
        comment: *mut u16,
        last_written: FileTime,
        credential_blob_size: u32,
        credential_blob: *mut u8,
        persist: u32,
        attribute_count: u32,
        attributes: *mut c_void,
        target_alias: *mut u16,
        user_name: *mut u16,
    }

    #[link(name = "advapi32")]
    unsafe extern "system" {
        fn CredWriteW(credential: *const CredentialW, flags: u32) -> i32;
        fn CredReadW(
            target_name: *const u16,
            cred_type: u32,
            flags: u32,
            credential: *mut *mut CredentialW,
        ) -> i32;
        fn CredDeleteW(target_name: *const u16, cred_type: u32, flags: u32) -> i32;
        fn CredFree(buffer: *const c_void);
    }

    fn to_wide_null(s: &str) -> Vec<u16> {
        std::ffi::OsStr::new(s)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect()
    }

    unsafe fn wide_ptr_to_string(ptr: *const u16) -> String {
        if ptr.is_null() {
            return String::new();
        }
        let mut len = 0usize;
        while unsafe { *ptr.add(len) } != 0 {
            len += 1;
        }
        let slice = unsafe { std::slice::from_raw_parts(ptr, len) };
        std::ffi::OsString::from_wide(slice)
            .to_string_lossy()
            .into_owned()
    }

    fn write_cred(
        target: &str,
        cred_type: u32,
        persist: u32,
        qualified_user: &str,
        password: &str,
    ) -> Result<()> {
        let mut target_w = to_wide_null(target);
        let mut user_w = to_wide_null(qualified_user);
        let mut blob_u16: Vec<u16> = password.encode_utf16().collect();
        let blob_bytes_len = (blob_u16.len() * 2) as u32;
        let raw = CredentialW {
            flags: 0,
            cred_type,
            target_name: target_w.as_mut_ptr(),
            comment: core::ptr::null_mut(),
            last_written: FileTime::default(),
            credential_blob_size: blob_bytes_len,
            credential_blob: if blob_u16.is_empty() {
                core::ptr::null_mut()
            } else {
                blob_u16.as_mut_ptr() as *mut u8
            },
            persist,
            attribute_count: 0,
            attributes: core::ptr::null_mut(),
            target_alias: core::ptr::null_mut(),
            user_name: user_w.as_mut_ptr(),
        };
        let ok = unsafe { CredWriteW(&raw, 0) };
        for w in &mut blob_u16 {
            unsafe { std::ptr::write_volatile(w, 0) };
        }
        if ok == 0 {
            let err = std::io::Error::last_os_error();
            bail!("CredWriteW failed for '{target}': {err}");
        }
        Ok(())
    }

    fn read_cred(target: &str, cred_type: u32) -> Result<Option<StoredRdpCredential>> {
        let target_w = to_wide_null(target);
        let mut ptr: *mut CredentialW = core::ptr::null_mut();
        let ok = unsafe { CredReadW(target_w.as_ptr(), cred_type, 0, &mut ptr) };
        if ok == 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(ERROR_NOT_FOUND as i32) {
                return Ok(None);
            }
            bail!("CredReadW failed for '{target}': {err}");
        }
        let res = unsafe {
            let c = &*ptr;
            let user_str = wide_ptr_to_string(c.user_name);
            let u16_len = (c.credential_blob_size as usize) / 2;
            let pw_str = if c.credential_blob.is_null() || u16_len == 0 {
                String::new()
            } else {
                let slice = std::slice::from_raw_parts(c.credential_blob as *const u16, u16_len);
                String::from_utf16_lossy(slice)
            };
            StoredRdpCredential::from_qualified_username(&user_str, pw_str)
        };
        unsafe { CredFree(ptr as *const c_void) };
        Ok(Some(res))
    }

    fn delete_cred(target: &str, cred_type: u32) -> Result<bool> {
        let target_w = to_wide_null(target);
        let ok = unsafe { CredDeleteW(target_w.as_ptr(), cred_type, 0) };
        if ok == 0 {
            let err = std::io::Error::last_os_error();
            if err.raw_os_error() == Some(ERROR_NOT_FOUND as i32) {
                return Ok(false);
            }
            bail!("CredDeleteW failed for '{target}': {err}");
        }
        Ok(true)
    }

    pub fn save(scope: &RdpCredentialScope, cred: &StoredRdpCredential) -> Result<()> {
        write_cred(
            &scope.store_target_name(),
            CRED_TYPE_GENERIC,
            CRED_PERSIST_LOCAL_MACHINE,
            &cred.qualified_username(),
            cred.password(),
        )
    }

    pub fn load(scope: &RdpCredentialScope) -> Result<Option<StoredRdpCredential>> {
        read_cred(&scope.store_target_name(), CRED_TYPE_GENERIC)
    }

    pub fn delete(scope: &RdpCredentialScope) -> Result<bool> {
        delete_cred(&scope.store_target_name(), CRED_TYPE_GENERIC)
    }

    pub fn install_windows_session_target(target: &str, cred: &StoredRdpCredential) -> Result<()> {
        if target.eq_ignore_ascii_case("TERMSRV/127.0.0.1")
            || target.eq_ignore_ascii_case("TERMSRV/localhost")
        {
            bail!(
                "refusing to write shared Windows credential target '{target}'; use a unique per-session 127.77.x.y loopback address"
            );
        }
        if windows_session_target_exists(target)? {
            bail!("refusing to overwrite existing Windows credential target '{target}'");
        }
        let domain_user = match cred.domain.as_deref() {
            Some(d) => format!(r"{d}\{}", cred.username),
            None if cred.username.contains('\\') || cred.username.contains('@') => {
                cred.username.clone()
            }
            None => format!(r".\{}", cred.username),
        };
        write_cred(
            target,
            CRED_TYPE_GENERIC,
            CRED_PERSIST_SESSION,
            &cred.qualified_username(),
            cred.password(),
        )?;
        let _ = write_cred(
            target,
            CRED_TYPE_DOMAIN_PASSWORD,
            CRED_PERSIST_SESSION,
            &domain_user,
            cred.password(),
        );
        Ok(())
    }

    pub fn windows_session_target_exists(target: &str) -> Result<bool> {
        Ok(read_cred(target, CRED_TYPE_GENERIC)?.is_some()
            || read_cred(target, CRED_TYPE_DOMAIN_PASSWORD)
                .unwrap_or(None)
                .is_some())
    }

    pub fn read_windows_session_target(target: &str) -> Result<Option<StoredRdpCredential>> {
        if let Some(c) = read_cred(target, CRED_TYPE_GENERIC)? {
            return Ok(Some(c));
        }
        Ok(read_cred(target, CRED_TYPE_DOMAIN_PASSWORD).unwrap_or(None))
    }

    pub fn remove_windows_session_target(target: &str) -> Result<bool> {
        let gen_removed = delete_cred(target, CRED_TYPE_GENERIC)?;
        let dom_removed = delete_cred(target, CRED_TYPE_DOMAIN_PASSWORD).unwrap_or(false);
        Ok(gen_removed || dom_removed)
    }
}

#[cfg(target_os = "linux")]
mod os_store {
    use super::{
        RdpCredentialScope, StoredRdpCredential, build_linux_secret_tool_store_plan,
        parse_linux_secret_tool_username,
    };
    use anyhow::{Context, Result, bail};
    use std::io::Write;
    use std::process::{Command, Stdio};

    pub fn save(scope: &RdpCredentialScope, cred: &StoredRdpCredential) -> Result<()> {
        let _ = delete(scope);
        let (prog, args, stdin_payload) = build_linux_secret_tool_store_plan(scope, cred)?;
        let mut child = Command::new(&prog)
            .args(&args)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .context("failed to spawn `secret-tool` (install libsecret-tools)")?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(stdin_payload.as_bytes())
                .context("failed to write secret to `secret-tool` stdin")?;
        }
        let out = child
            .wait_with_output()
            .context("failed waiting for `secret-tool store`")?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            bail!("`secret-tool store` failed: {}", stderr.trim());
        }
        Ok(())
    }

    pub fn load(scope: &RdpCredentialScope) -> Result<Option<StoredRdpCredential>> {
        let pw_out = Command::new("secret-tool")
            .args([
                "lookup",
                "service",
                "meshharbor-rdp",
                "org",
                &scope.org_id,
                "device",
                &scope.device_id,
            ])
            .stdin(Stdio::null())
            .output()
            .context("failed to run `secret-tool lookup`")?;
        if !pw_out.status.success() {
            return Ok(None);
        }
        let pw = String::from_utf8_lossy(&pw_out.stdout)
            .trim_end_matches(&['\r', '\n'][..])
            .to_string();
        if pw.is_empty() {
            return Ok(None);
        }
        let out = Command::new("secret-tool")
            .args([
                "search",
                "--all",
                "service",
                "meshharbor-rdp",
                "org",
                &scope.org_id,
                "device",
                &scope.device_id,
            ])
            .stdin(Stdio::null())
            .output()
            .context("failed to run `secret-tool search`")?;
        let combined = format!(
            "{}\n{}",
            String::from_utf8_lossy(&out.stderr),
            String::from_utf8_lossy(&out.stdout)
        );
        let user = parse_linux_secret_tool_username(&combined).with_context(|| {
            format!(
                "invalid stored credential for {}",
                scope.store_target_name()
            )
        })?;
        Ok(Some(StoredRdpCredential::from_qualified_username(
            &user, pw,
        )))
    }

    pub fn delete(scope: &RdpCredentialScope) -> Result<bool> {
        let out = Command::new("secret-tool")
            .args([
                "clear",
                "service",
                "meshharbor-rdp",
                "org",
                &scope.org_id,
                "device",
                &scope.device_id,
            ])
            .stdin(Stdio::null())
            .output()
            .context("failed to run `secret-tool clear`")?;
        Ok(out.status.success())
    }

    pub fn install_windows_session_target(
        _target: &str,
        _cred: &StoredRdpCredential,
    ) -> Result<()> {
        bail!("WindowsSessionTargetGuard is only supported on Windows")
    }

    pub fn windows_session_target_exists(_target: &str) -> Result<bool> {
        bail!("WindowsSessionTargetGuard is only supported on Windows")
    }

    pub fn read_windows_session_target(_target: &str) -> Result<Option<StoredRdpCredential>> {
        bail!("WindowsSessionTargetGuard is only supported on Windows")
    }

    pub fn remove_windows_session_target(_target: &str) -> Result<bool> {
        Ok(false)
    }
}

#[cfg(target_os = "macos")]
mod os_store {
    use super::{RdpCredentialScope, StoredRdpCredential, build_macos_security_store_plan};
    use anyhow::{Context, Result, bail};
    use std::io::Write;
    use std::process::{Command, Stdio};

    pub fn save(scope: &RdpCredentialScope, cred: &StoredRdpCredential) -> Result<()> {
        let (prog, args, stdin_payload) = build_macos_security_store_plan(scope, cred)?;
        let mut child = Command::new(&prog)
            .args(&args)
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .context("failed to spawn `/usr/bin/security -i`")?;
        if let Some(mut stdin) = child.stdin.take() {
            stdin
                .write_all(stdin_payload.as_bytes())
                .context("failed writing to `/usr/bin/security -i` stdin")?;
        }
        let out = child
            .wait_with_output()
            .context("failed waiting for `/usr/bin/security -i`")?;
        if !out.status.success() {
            let stderr = String::from_utf8_lossy(&out.stderr);
            bail!("`/usr/bin/security -i` failed: {}", stderr.trim());
        }
        Ok(())
    }

    pub fn load(scope: &RdpCredentialScope) -> Result<Option<StoredRdpCredential>> {
        let service = scope.store_target_name();
        let meta = Command::new("/usr/bin/security")
            .args(["find-generic-password", "-s", &service])
            .stdin(Stdio::null())
            .output()
            .context("failed to run `/usr/bin/security find-generic-password`")?;
        if !meta.status.success() {
            return Ok(None);
        }
        let stdout = String::from_utf8_lossy(&meta.stdout);
        let mut acct = String::new();
        for line in stdout.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("\"acct\"<blob>=") {
                if let Some((_, rhs)) = trimmed.split_once('=') {
                    acct = rhs.trim().trim_matches('"').to_string();
                    break;
                }
            }
        }
        let pw_out = Command::new("/usr/bin/security")
            .args(["find-generic-password", "-s", &service, "-w"])
            .stdin(Stdio::null())
            .output()
            .context("failed to read password from macOS Keychain")?;
        if !pw_out.status.success() {
            return Ok(None);
        }
        let pw = String::from_utf8_lossy(&pw_out.stdout)
            .trim_end_matches(&['\r', '\n'][..])
            .to_string();
        if pw.is_empty() {
            return Ok(None);
        }
        if acct.trim().is_empty() {
            bail!(
                "stored RDP credential in macOS Keychain for '{}' is missing account/username attribute; refusing fallback username",
                service
            );
        }
        Ok(Some(StoredRdpCredential::from_qualified_username(
            acct.trim(),
            pw,
        )))
    }

    pub fn delete(scope: &RdpCredentialScope) -> Result<bool> {
        let service = scope.store_target_name();
        let out = Command::new("/usr/bin/security")
            .args(["delete-generic-password", "-s", &service])
            .stdin(Stdio::null())
            .output()
            .context("failed to run `/usr/bin/security delete-generic-password`")?;
        Ok(out.status.success())
    }

    pub fn install_windows_session_target(
        _target: &str,
        _cred: &StoredRdpCredential,
    ) -> Result<()> {
        bail!("WindowsSessionTargetGuard is only supported on Windows")
    }

    pub fn windows_session_target_exists(_target: &str) -> Result<bool> {
        bail!("WindowsSessionTargetGuard is only supported on Windows")
    }

    pub fn read_windows_session_target(_target: &str) -> Result<Option<StoredRdpCredential>> {
        bail!("WindowsSessionTargetGuard is only supported on Windows")
    }

    pub fn remove_windows_session_target(_target: &str) -> Result<bool> {
        Ok(false)
    }
}

/// Strictly resolve a target device and its owning organization's real
/// `tenant_id` and `node_id` from the local daemon's `NodeStatus` and
/// `PeerInfo` table. Fails closed if the peer is unknown, ambiguous across
/// organizations, or missing a real `tenant_id`, `node_id`, or `overlay_ip`.
pub fn resolve_peer_scope(
    status: &localapi::NodeStatus,
    peers: &[localapi::PeerInfo],
    target_host: &str,
) -> Result<(ResolvedRdpDevice, String, Option<u16>)> {
    let trimmed = target_host.trim();
    if trimmed.is_empty() {
        bail!("target device must not be empty");
    }

    let (org_filter, peer_selector) = match trimmed.split_once('/') {
        Some((org_part, host_part)) => {
            let o = org_part.trim();
            let h = host_part.trim();
            if o.is_empty() || h.is_empty() {
                bail!("invalid '<org>/<device>' target '{trimmed}'");
            }
            (Some(o), h)
        }
        None => (None, trimmed),
    };

    let matches: Vec<&localapi::PeerInfo> = peers
        .iter()
        .filter(|p| {
            if let Some(of) = org_filter {
                let org_matches_label = p.org.eq_ignore_ascii_case(of)
                    || (p.org.is_empty() && of.eq_ignore_ascii_case("primary"));
                let org_matches_tenant = status
                    .orgs
                    .iter()
                    .find(|o| {
                        o.label.eq_ignore_ascii_case(&p.org)
                            || (p.org.is_empty() && o.primary)
                            || (p.org.eq_ignore_ascii_case("primary") && o.primary)
                    })
                    .and_then(|o| o.tenant_id.as_deref())
                    .is_some_and(|tid| tid.eq_ignore_ascii_case(of));
                if !org_matches_label && !org_matches_tenant {
                    return false;
                }
            }
            p.node_id.eq_ignore_ascii_case(peer_selector)
                || p.agent_id
                    .as_deref()
                    .is_some_and(|aid| aid.eq_ignore_ascii_case(peer_selector))
                || p.name.eq_ignore_ascii_case(peer_selector)
                || p.overlay_ip.as_deref() == Some(peer_selector)
        })
        .collect();

    if matches.is_empty() {
        bail!(
            "target device '{trimmed}' was not found in the local daemon peer list; refusing to fall back to an unverified device name"
        );
    }
    if matches.len() > 1 {
        bail!(
            "target device '{trimmed}' is ambiguous across {} peers/organizations; specify the exact node_id or '<org>/<device>'",
            matches.len()
        );
    }

    let peer = matches[0];
    let device_id = {
        let nid = peer.node_id.trim();
        if !nid.is_empty() && !nid.eq_ignore_ascii_case(&peer.name) {
            nid.to_string()
        } else if let Some(aid) = peer
            .agent_id
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
        {
            aid.to_string()
        } else if !nid.is_empty() {
            nid.to_string()
        } else {
            bail!(
                "peer '{}' has no real node_id or agent_id; refusing to derive credential scope",
                peer.name
            );
        }
    };

    let peer_org_label = peer.org.trim();
    let resolved_tenant_id: Option<&str> = if !status.orgs.is_empty() {
        if !peer_org_label.is_empty() {
            status
                .orgs
                .iter()
                .find(|o| {
                    o.label.eq_ignore_ascii_case(peer_org_label)
                        || (peer_org_label.eq_ignore_ascii_case("primary") && o.primary)
                })
                .and_then(|o| {
                    o.tenant_id.as_deref().or(if o.primary {
                        status.tenant_id.as_deref()
                    } else {
                        None
                    })
                })
        } else if status.orgs.len() == 1 {
            status.orgs[0]
                .tenant_id
                .as_deref()
                .or(status.tenant_id.as_deref())
        } else {
            None
        }
    } else if peer_org_label.is_empty() || peer_org_label.eq_ignore_ascii_case("primary") {
        status.tenant_id.as_deref()
    } else {
        None
    };

    let org_id = resolved_tenant_id
        .map(str::trim)
        .filter(|tid| !tid.is_empty() && !tid.eq_ignore_ascii_case("primary"))
        .ok_or_else(|| {
            anyhow::anyhow!(
                "cannot resolve real tenant_id for device '{}' (org '{}'); refusing to fall back to label",
                peer.name,
                peer.org
            )
        })?
        .to_string();

    let dial_ip = peer
        .overlay_ip
        .as_deref()
        .map(str::trim)
        .filter(|ip| !ip.is_empty())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "device '{}' ({}) has no overlay IP in the local daemon peer list",
                peer.name,
                device_id
            )
        })?
        .to_string();

    let device_name = if peer.name.trim().is_empty() {
        device_id.clone()
    } else {
        peer.name.trim().to_string()
    };

    Ok((
        ResolvedRdpDevice {
            org_id,
            device_id,
            device_name,
            rdp_available: None,
            rdp_port: None,
            rdp_cert_sha256: None,
        },
        dial_ip,
        status.overlay_socks5_port,
    ))
}

/// Enrich a [`ResolvedRdpDevice`] with server-reported RDP metadata
/// (`rdp_available`, `rdp_port`, `rdp_cert_sha256`) from LocalAPI `devices` rows.
pub fn enrich_device_rdp_metadata(
    device: &mut ResolvedRdpDevice,
    agent_id_hint: Option<&str>,
    overlay_ip_hint: Option<&str>,
    rows: &[localapi::DeviceRowLite],
) {
    let matched: Vec<&localapi::DeviceRowLite> = rows
        .iter()
        .filter(|r| {
            (r.kind.is_empty() || r.kind.eq_ignore_ascii_case("agent"))
                && (r
                    .overlay_node_id
                    .as_deref()
                    .is_some_and(|nid| nid.eq_ignore_ascii_case(&device.device_id))
                    || r.id.eq_ignore_ascii_case(&device.device_id)
                    || agent_id_hint
                        .filter(|s| !s.is_empty())
                        .is_some_and(|aid| r.id.eq_ignore_ascii_case(aid))
                    || overlay_ip_hint
                        .filter(|s| !s.is_empty())
                        .is_some_and(|ip| r.overlay_ip.as_deref() == Some(ip)))
        })
        .collect();
    if matched.len() == 1 {
        let row = matched[0];
        device.rdp_available = row.rdp_available;
        device.rdp_port = row.rdp_port.filter(|&p| p > 0);
        device.rdp_cert_sha256 = row
            .rdp_cert_sha256
            .as_deref()
            .and_then(|s| normalize_cert_sha256(s).ok());
    }
}

/// Connect to the local MeshHarbor daemon (`meshharbord`) over LocalAPI and
/// resolve `(ResolvedRdpDevice, dial_ip, overlay_socks5_port)` for `target_host`,
/// enriching RDP port/certificate metadata from `GET /api/agent/self/devices`
/// when available within a bounded 1.5 s window.
pub async fn resolve_target_device(
    target_host: &str,
) -> Result<(ResolvedRdpDevice, String, Option<u16>)> {
    let mut client = localapi::connect().await.context(
        "failed to connect to local MeshHarbor daemon (meshharbord) to resolve device identity",
    )?;
    let status = client
        .status()
        .await
        .context("failed to query local daemon status for organization tenant_id")?;
    let peers = client
        .peers()
        .await
        .context("failed to query local daemon peer list for device identity")?;
    let (mut device, dial_ip, socks_port) = resolve_peer_scope(&status, &peers, target_host)?;

    let matched_peer = peers.iter().find(|p| {
        p.overlay_ip.as_deref() == Some(dial_ip.as_str())
            && (p.node_id.eq_ignore_ascii_case(&device.device_id)
                || p.agent_id
                    .as_deref()
                    .is_some_and(|aid| aid.eq_ignore_ascii_case(&device.device_id)))
    });
    let org_label = matched_peer
        .map(|p| p.org.trim())
        .filter(|o| !o.is_empty() && !o.eq_ignore_ascii_case(crate::config::PRIMARY_ORG_LABEL))
        .unwrap_or("");
    let agent_id_hint = matched_peer.and_then(|p| p.agent_id.as_deref());
    let query = localapi::DevicesQuery {
        page: 1,
        per_page: 100,
        q: Some(dial_ip.clone()),
        sort: None,
        dir: None,
    };
    if let Ok(Ok(page)) = tokio::time::timeout(
        Duration::from_millis(1500),
        client.devices(org_label, &query),
    )
    .await
    {
        enrich_device_rdp_metadata(&mut device, agent_id_hint, Some(&dial_ip), &page.items);
    }

    Ok((device, dial_ip, socks_port))
}

/// Phase C no-op credential store: credentials are always prompted directly by
/// the OS native RDP client (`mstsc.exe` / FreeRDP); Phase C collects no
/// passwords and keeps passwordless RDP off by default.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoSavedRdpCredentialStore;

impl RdpCredentialStore for NoSavedRdpCredentialStore {
    fn save(&self, _scope: &RdpCredentialScope, _cred: &StoredRdpCredential) -> Result<()> {
        bail!("Phase C desktop RDP launch does not save credentials")
    }

    fn load(&self, _scope: &RdpCredentialScope) -> Result<Option<StoredRdpCredential>> {
        Ok(None)
    }

    fn delete(&self, _scope: &RdpCredentialScope) -> Result<bool> {
        Ok(false)
    }
}

/// Construct [`RdpCliOptions`] for the desktop `cmd_open_rdp` command.
///
/// Enforces Phase C invariants:
/// - Rejects empty targets, flag-like targets (`-` or `/`), `@` user prefixes, or
///   whitespace/control characters.
/// - Defaults `port` to `3389` when `None` or `0`.
/// - Keeps passwordless RDP strictly disabled (`save_credentials = false`,
///   `use_saved_credentials = false`, `no_saved_credentials = true`) and passes
///   zero extra arguments (`extra_args = []`).
pub fn build_open_rdp_options(
    target: &str,
    org: Option<&str>,
    port: Option<u16>,
    cert_sha256: Option<&str>,
    platform: &str,
) -> std::result::Result<RdpCliOptions, String> {
    let raw_target = target.trim();
    if raw_target.is_empty() {
        return Err("RDP target device must not be empty".to_string());
    }
    if raw_target.starts_with('-') || raw_target.starts_with('/') {
        return Err("invalid RDP target device selector".to_string());
    }
    if raw_target.contains('@')
        || raw_target
            .chars()
            .any(|c| c.is_whitespace() || c.is_control())
    {
        return Err(
            "invalid RDP target device selector (must not contain credentials or whitespace)"
                .to_string(),
        );
    }
    let org_clean = org
        .map(str::trim)
        .filter(|o| !o.is_empty() && !o.eq_ignore_ascii_case(crate::config::PRIMARY_ORG_LABEL));
    if let Some(o) = org_clean
        && (o.contains('/')
            || o.contains('@')
            || o.chars().any(|c| c.is_whitespace() || c.is_control()))
    {
        return Err("invalid organization label for RDP target".to_string());
    }
    let selector = match (org_clean, raw_target.contains('/')) {
        (Some(o), false) => format!("{o}/{raw_target}"),
        _ => raw_target.to_string(),
    };
    let explicit_port = port.filter(|&p| p > 0);
    let effective_port = explicit_port.unwrap_or(3389);
    let _ = platform;
    let effective_cert = cert_sha256
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(ToOwned::to_owned);
    Ok(RdpCliOptions {
        target: selector,
        user: None,
        domain: None,
        port: effective_port,
        explicit_port,
        cert_sha256: effective_cert,
        check: false,
        save_credentials: false,
        use_saved_credentials: false,
        clear_credentials: false,
        no_saved_credentials: true,
        extra_args: Vec::new(),
    })
}

/// Pure invocation planner for desktop `cmd_open_rdp` that constructs the native
/// RDP client command line (`mstsc.exe` on Windows, FreeRDP on Linux/macOS) and
/// guarantees that zero passwords or credentials appear in `args`, `env`, or
/// `stdin_payload`.
pub fn plan_desktop_open_rdp_invocation(
    device: &ResolvedRdpDevice,
    local_tunnel_addr: SocketAddr,
    port: Option<u16>,
    cert_sha256: Option<&str>,
    platform: &str,
) -> std::result::Result<PlannedRdpInvocation, String> {
    let opts = build_open_rdp_options(&device.device_id, None, port, cert_sha256, platform)?;
    let store = NoSavedRdpCredentialStore;
    let plan = plan_rdp_session(
        &opts,
        device,
        local_tunnel_addr,
        &store,
        None,
        Some("1"),
        platform,
    )
    .map_err(|e| e.to_string())?
    .ok_or_else(|| "RDP session planner returned no client invocation".to_string())?;
    if plan.stdin_payload.is_some() || plan.windows_session_target.is_some() || !plan.env.is_empty()
    {
        return Err("Phase C desktop RDP invocation must not carry credentials".to_string());
    }
    Ok(plan)
}

/// Canonical per-target key `(org_id, device_id)` used to deduplicate
/// concurrent desktop RDP sessions for the same target device.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DesktopRdpTargetKey {
    pub org_id: String,
    pub device_id: String,
}

impl DesktopRdpTargetKey {
    pub fn from_device(device: &ResolvedRdpDevice) -> Self {
        Self {
            org_id: device.org_id.trim().to_ascii_lowercase(),
            device_id: device.device_id.trim().to_ascii_lowercase(),
        }
    }
}

/// Registry of currently running desktop RDP sessions keyed by target device.
/// Ensures repeated `openRdp` / `cmd_open_rdp` calls for the same target while
/// an RDP client is already running do not spawn duplicate `mstsc` processes or
/// loopback tunnels, and releases the slot automatically when the session exits.
#[derive(Default, Clone)]
pub struct DesktopRdpSessionRegistry {
    active: std::sync::Arc<std::sync::Mutex<std::collections::HashSet<DesktopRdpTargetKey>>>,
}

/// RAII guard that releases a target device's active RDP session slot on drop.
pub struct ActiveDesktopRdpSessionGuard {
    active: std::sync::Arc<std::sync::Mutex<std::collections::HashSet<DesktopRdpTargetKey>>>,
    key: DesktopRdpTargetKey,
}

impl Drop for ActiveDesktopRdpSessionGuard {
    fn drop(&mut self) {
        let mut set = self.active.lock().unwrap_or_else(|p| p.into_inner());
        set.remove(&self.key);
    }
}

impl DesktopRdpSessionRegistry {
    pub fn try_acquire(&self, device: &ResolvedRdpDevice) -> Option<ActiveDesktopRdpSessionGuard> {
        let key = DesktopRdpTargetKey::from_device(device);
        let mut set = self.active.lock().unwrap_or_else(|p| p.into_inner());
        if !set.insert(key.clone()) {
            return None;
        }
        Some(ActiveDesktopRdpSessionGuard {
            active: std::sync::Arc::clone(&self.active),
            key,
        })
    }

    pub fn is_active(&self, device: &ResolvedRdpDevice) -> bool {
        let key = DesktopRdpTargetKey::from_device(device);
        self.active
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .contains(&key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cmd_open_rdp_argument_construction_contains_zero_passwords_and_validates_inputs() {
        let device = ResolvedRdpDevice {
            org_id: "66366f7a7230306d6c657231".to_string(),
            device_id: "66366f7a7230306d6c657232".to_string(),
            device_name: "surface-pro".to_string(),
            ..Default::default()
        };
        let tunnel_addr: SocketAddr = "127.77.12.34:54321".parse().unwrap();
        let cert_fp = "aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99:aa:bb:cc:dd:ee:ff:00:11:22:33:44:55:66:77:88:99";

        // 1. Windows (`mstsc.exe`): only `/v:127.77.12.34:54321`, zero passwords in args/env/stdin.
        let win_plan = plan_desktop_open_rdp_invocation(
            &device,
            tunnel_addr,
            Some(3389),
            Some(cert_fp),
            "windows",
        )
        .unwrap();
        assert_eq!(win_plan.program, "mstsc.exe");
        assert_eq!(win_plan.args, vec!["/v:127.77.12.34:54321".to_string()]);
        assert!(win_plan.stdin_payload.is_none());
        assert!(win_plan.windows_session_target.is_none());
        assert!(win_plan.env.is_empty());
        for arg in &win_plan.args {
            let lower = arg.to_ascii_lowercase();
            assert!(!lower.contains("pass"));
            assert!(!lower.starts_with("/p:"));
            assert!(!lower.starts_with("/u:"));
            assert!(!lower.contains("cmdkey"));
        }

        // 2. Linux/macOS (`xfreerdp3`): `/v:127.77.12.34:54321` + `/cert:fingerprint:sha256:...`, zero passwords.
        let linux_plan = plan_desktop_open_rdp_invocation(
            &device,
            tunnel_addr,
            Some(3390),
            Some(cert_fp),
            "linux",
        )
        .unwrap();
        assert_eq!(
            linux_plan.args,
            vec![
                "/v:127.77.12.34:54321".to_string(),
                format!("/cert:fingerprint:sha256:{cert_fp}"),
            ]
        );
        assert!(linux_plan.stdin_payload.is_none());
        assert!(linux_plan.windows_session_target.is_none());
        assert!(linux_plan.env.is_empty());
        for arg in &linux_plan.args {
            let lower = arg.to_ascii_lowercase();
            assert!(!lower.contains("pass"));
            assert!(!lower.starts_with("/p:"));
            assert!(!lower.starts_with("-p"));
            assert!(!lower.contains("from-stdin"));
        }

        // 3. Rejects credential-bearing or flag-injection targets.
        assert!(
            build_open_rdp_options("alice@surface-pro", None, Some(3389), None, "windows").is_err()
        );
        assert!(build_open_rdp_options("/p:secret", None, Some(3389), None, "windows").is_err());
        assert!(build_open_rdp_options("-p", None, Some(3389), None, "windows").is_err());
        assert!(build_open_rdp_options("surface pro", None, Some(3389), None, "windows").is_err());

        // 4. Secondary org prefixing and port default.
        let opts =
            build_open_rdp_options("surface-pro", Some("acme"), None, None, "windows").unwrap();
        assert_eq!(opts.target, "acme/surface-pro");
        assert_eq!(opts.port, 3389);
        assert!(!opts.save_credentials);
        assert!(!opts.use_saved_credentials);
        assert!(opts.no_saved_credentials);
    }

    #[tokio::test]
    async fn socks5_client_connect_frames_rfc1928_no_auth_domain_connect_and_consumes_bnd_addr() {
        let (mut client, mut server) = tokio::io::duplex(256);
        let srv = tokio::spawn(async move {
            let mut greet = [0u8; 3];
            server.read_exact(&mut greet).await.unwrap();
            assert_eq!(greet, [0x05, 0x01, 0x00]);
            server.write_all(&[0x05, 0x00]).await.unwrap();

            let mut req_head = [0u8; 5];
            server.read_exact(&mut req_head).await.unwrap();
            assert_eq!(&req_head[..4], &[0x05, 0x01, 0x00, 0x03]);
            let dlen = req_head[4] as usize;
            let mut host = vec![0u8; dlen];
            server.read_exact(&mut host).await.unwrap();
            assert_eq!(std::str::from_utf8(&host).unwrap(), "100.64.0.42");
            let mut port = [0u8; 2];
            server.read_exact(&mut port).await.unwrap();
            assert_eq!(u16::from_be_bytes(port), 3389);

            // Reply REP=0x00 with ATYP=IPv4 127.0.0.1:0 followed by RDP greeting byte.
            server
                .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0, 0x03])
                .await
                .unwrap();
        });

        socks5_client_connect(&mut client, "100.64.0.42", 3389)
            .await
            .unwrap();
        // Stream must sit cleanly at the first payload byte after BND.ADDR + BND.PORT.
        let first_payload = client.read_u8().await.unwrap();
        assert_eq!(first_payload, 0x03);
        srv.await.unwrap();
    }

    #[test]
    fn desktop_rdp_session_registry_deduplicates_per_target_and_releases_on_exit() {
        let registry = DesktopRdpSessionRegistry::default();
        let dev_a = ResolvedRdpDevice {
            org_id: "66366f7a7230306d6c657231".to_string(),
            device_id: "66366f7a7230306d6c657232".to_string(),
            device_name: "surface-pro".to_string(),
            ..Default::default()
        };
        let dev_a_upper = ResolvedRdpDevice {
            org_id: "66366F7A7230306D6C657231".to_string(),
            device_id: "66366F7A7230306D6C657232".to_string(),
            device_name: "surface-pro".to_string(),
            ..Default::default()
        };
        let dev_b = ResolvedRdpDevice {
            org_id: "66366f7a7230306d6c657231".to_string(),
            device_id: "66366f7a7230306d6c657299".to_string(),
            device_name: "workstation-b".to_string(),
            ..Default::default()
        };

        assert!(!registry.is_active(&dev_a));
        let guard_a = registry
            .try_acquire(&dev_a)
            .expect("first session for dev_a should acquire");
        assert!(registry.is_active(&dev_a));

        // Duplicate request for the same target (including case variation) is rejected while active.
        assert!(registry.try_acquire(&dev_a).is_none());
        assert!(registry.try_acquire(&dev_a_upper).is_none());

        // A different target device can still start concurrently.
        let guard_b = registry
            .try_acquire(&dev_b)
            .expect("concurrent session for dev_b should acquire");
        assert!(registry.is_active(&dev_b));

        // Dropping guard_a (when child RDP process exits) releases dev_a so a subsequent session can start.
        drop(guard_a);
        assert!(!registry.is_active(&dev_a));
        assert!(registry.is_active(&dev_b));

        let guard_a2 = registry
            .try_acquire(&dev_a)
            .expect("after exit, dev_a can acquire again");
        assert!(registry.is_active(&dev_a));
        drop(guard_a2);
        drop(guard_b);
        assert!(!registry.is_active(&dev_a));
        assert!(!registry.is_active(&dev_b));
    }

    fn generate_test_cert(
        cn: &str,
    ) -> (
        CertificateDer<'static>,
        rustls_pki_types::PrivateKeyDer<'static>,
        String,
    ) {
        let certified = rcgen::generate_simple_self_signed(vec![cn.to_string()]).unwrap();
        let cert_der = CertificateDer::from(certified.cert.der().to_vec());
        let fp = format_sha256_colon_hex(cert_der.as_ref());
        let key = rustls_pki_types::PrivateKeyDer::Pkcs8(
            rustls_pki_types::PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der()),
        );
        (cert_der, key, fp)
    }

    fn x224_cc_neg_rsp(selected_protocol: u32) -> [u8; 19] {
        let p = selected_protocol.to_le_bytes();
        [
            0x03, 0x00, 0x00, 0x13, // TPKT v3, len=19
            0x0e, // LI=14
            0xd0, // X.224 CC
            0x00, 0x00, 0x12, 0x34, 0x00, // refs + class
            0x02, // TYPE_RDP_NEG_RSP
            0x00, // flags
            0x08, 0x00, // length=8 (LE)
            p[0], p[1], p[2], p[3],
        ]
    }

    fn x224_cc_neg_failure(failure_code: u32) -> [u8; 19] {
        let c = failure_code.to_le_bytes();
        [
            0x03, 0x00, 0x00, 0x13, // TPKT v3, len=19
            0x0e, // LI=14
            0xd0, // X.224 CC
            0x00, 0x00, 0x12, 0x34, 0x00, 0x03, // TYPE_RDP_NEG_FAILURE
            0x00, 0x08, 0x00, c[0], c[1], c[2], c[3],
        ]
    }

    #[tokio::test]
    async fn precheck_valid_cert_passes_and_same_loopback_listener_serves_second_tls_connection() {
        let (cert_der, key_der, good_fp) = generate_test_cert("surface-rdp.local");
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let srv_tls = rustls::ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der)
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(srv_tls));

        let upstream = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let upstream_port = upstream.local_addr().unwrap().port();
        let (done_tx, mut done_rx) = tokio::sync::mpsc::unbounded_channel::<usize>();
        let served_count = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let served_clone = Arc::clone(&served_count);
        let srv_task = tokio::spawn(async move {
            while let Ok((mut stream, _)) = upstream.accept().await {
                let acc = acceptor.clone();
                let ctr = Arc::clone(&served_clone);
                let tx = done_tx.clone();
                tokio::spawn(async move {
                    let mut req = [0u8; 19];
                    stream.read_exact(&mut req).await.unwrap();
                    assert_eq!(req, X224_TLS_CONNECTION_REQUEST);
                    stream
                        .write_all(&x224_cc_neg_rsp(X224_PROTOCOL_HYBRID))
                        .await
                        .unwrap();
                    let mut tls = acc.accept(stream).await.unwrap();
                    let n = ctr.fetch_add(1, Ordering::SeqCst) + 1;
                    let _ = tx.send(n);
                    let _ = tls.shutdown().await;
                });
            }
        });

        let tunnel_listener = bind_unique_session_loopback_listener().await.unwrap();
        let local_addr = tunnel_listener.local_addr().unwrap();
        let (pump, probe) = spawn_rdp_loopback_tunnel_with_probe(
            tunnel_listener,
            "127.0.0.1".to_string(),
            upstream_port,
            None,
        );

        // Connection #1: pre-check verifies pinned leaf SHA-256 over `127.77.x.y:<port>`.
        let out1 = precheck_rdp_tunnel_tls(
            local_addr,
            &probe,
            "surface-rdp",
            upstream_port,
            Some(&good_fp),
        )
        .await
        .expect("connection #1 precheck should succeed");
        assert!(out1.pinned_verified);
        assert_eq!(out1.selected_protocol, X224_PROTOCOL_HYBRID);
        assert_eq!(out1.leaf_cert_sha256.as_deref(), Some(good_fp.as_str()));
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), done_rx.recv())
                .await
                .unwrap(),
            Some(1)
        );

        // Connection #2 (`V0028 §3`): second X.224 + TLS connection on the EXACT SAME
        // `127.77.x.y:<port>` listener (simulating `mstsc.exe` connecting right after precheck).
        let out2 = precheck_rdp_tunnel_tls(
            local_addr,
            &probe,
            "surface-rdp",
            upstream_port,
            Some(&good_fp),
        )
        .await
        .expect("connection #2 on same 127.77.x.y listener should succeed");
        assert!(out2.pinned_verified);
        assert_eq!(out2.leaf_cert_sha256.as_deref(), Some(good_fp.as_str()));
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), done_rx.recv())
                .await
                .unwrap(),
            Some(2)
        );
        assert_eq!(served_count.load(Ordering::SeqCst), 2);

        pump.abort();
        srv_task.abort();
    }

    #[tokio::test]
    async fn precheck_fails_closed_on_cert_fingerprint_mismatch() {
        let (cert_a, key_a, actual_fp) = generate_test_cert("rdp-actual.local");
        let (_cert_b, _key_b, expected_fp) = generate_test_cert("rdp-expected.local");
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let srv_tls = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert_a], key_a)
            .unwrap();
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(srv_tls));

        let upstream = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let upstream_port = upstream.local_addr().unwrap().port();
        let srv_task = tokio::spawn(async move {
            if let Ok((mut stream, _)) = upstream.accept().await {
                let mut req = [0u8; 19];
                stream.read_exact(&mut req).await.unwrap();
                stream
                    .write_all(&x224_cc_neg_rsp(X224_PROTOCOL_SSL))
                    .await
                    .unwrap();
                if let Ok(mut tls) = acceptor.accept(stream).await {
                    let _ = tls.shutdown().await;
                }
            }
        });

        let listener = bind_unique_session_loopback_listener().await.unwrap();
        let local_addr = listener.local_addr().unwrap();
        let (pump, probe) = spawn_rdp_loopback_tunnel_with_probe(
            listener,
            "127.0.0.1".to_string(),
            upstream_port,
            None,
        );

        let err = precheck_rdp_tunnel_tls(
            local_addr,
            &probe,
            "target-mismatch",
            upstream_port,
            Some(&expected_fp),
        )
        .await
        .expect_err("mismatched fingerprint must fail closed");
        match &err {
            RdpPrecheckError::FingerprintMismatch {
                expected, actual, ..
            } => {
                assert_eq!(expected, &expected_fp);
                assert_eq!(actual, &actual_fp);
            }
            other => panic!("expected FingerprintMismatch, got {other:?}"),
        }
        assert!(err.to_string().contains("指纹不匹配"));

        pump.abort();
        srv_task.abort();
    }

    #[tokio::test]
    async fn precheck_fails_closed_on_protocol_rdp_downgrade_and_neg_failure() {
        for (label, response_bytes) in [
            ("protocol_rdp_0", x224_cc_neg_rsp(X224_PROTOCOL_RDP)),
            ("neg_failure_2", x224_cc_neg_failure(0x0000_0002)),
        ] {
            let upstream = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
                .await
                .unwrap();
            let upstream_port = upstream.local_addr().unwrap().port();
            let srv_task = tokio::spawn(async move {
                if let Ok((mut stream, _)) = upstream.accept().await {
                    let mut req = [0u8; 19];
                    let _ = stream.read_exact(&mut req).await;
                    let _ = stream.write_all(&response_bytes).await;
                }
            });

            let listener = bind_unique_session_loopback_listener().await.unwrap();
            let local_addr = listener.local_addr().unwrap();
            let (pump, probe) = spawn_rdp_loopback_tunnel_with_probe(
                listener,
                "127.0.0.1".to_string(),
                upstream_port,
                None,
            );

            let err = precheck_rdp_tunnel_tls(local_addr, &probe, label, upstream_port, None)
                .await
                .expect_err("downgrade or neg_failure must fail closed");
            assert!(
                matches!(err, RdpPrecheckError::ProtocolDowngrade { .. }),
                "case {label}: expected ProtocolDowngrade, got {err:?}"
            );
            assert!(err.to_string().contains("降级") || err.to_string().contains("拒绝 TLS"));

            pump.abort();
            srv_task.abort();
        }
    }

    #[derive(Debug)]
    struct MismatchedKeyCertResolver(Arc<rustls::sign::CertifiedKey>);

    impl rustls::server::ResolvesServerCert for MismatchedKeyCertResolver {
        fn resolve(
            &self,
            _client_hello: rustls::server::ClientHello<'_>,
        ) -> Option<Arc<rustls::sign::CertifiedKey>> {
            Some(Arc::clone(&self.0))
        }
    }

    #[tokio::test]
    async fn precheck_fails_closed_on_invalid_tls_signature_or_legacy_tls_version() {
        // Subcase A: Server presents `cert_a` (even matching `expected_fp`!),
        // but signs the TLS handshake transcript with `key_b` (wrong private key).
        // `ring` handshake signature verification must reject with `TlsInvalid`.
        let (cert_a, _key_a, fp_a) = generate_test_cert("cert-a.local");
        let (_cert_b, key_b, _fp_b) = generate_test_cert("cert-b.local");
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let signing_key_b = provider.key_provider.load_private_key(key_b).unwrap();
        let forged_ck = Arc::new(rustls::sign::CertifiedKey::new(vec![cert_a], signing_key_b));
        let srv_tls = rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_cert_resolver(Arc::new(MismatchedKeyCertResolver(forged_ck)));
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(srv_tls));

        let upstream_a = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let port_a = upstream_a.local_addr().unwrap().port();
        let srv_a = tokio::spawn(async move {
            if let Ok((mut stream, _)) = upstream_a.accept().await {
                let mut req = [0u8; 19];
                let _ = stream.read_exact(&mut req).await;
                let _ = stream
                    .write_all(&x224_cc_neg_rsp(X224_PROTOCOL_HYBRID))
                    .await;
                let _ = acceptor.accept(stream).await;
            }
        });
        let listener_a = bind_unique_session_loopback_listener().await.unwrap();
        let addr_a = listener_a.local_addr().unwrap();
        let (pump_a, probe_a) =
            spawn_rdp_loopback_tunnel_with_probe(listener_a, "127.0.0.1".into(), port_a, None);

        let err_a = precheck_rdp_tunnel_tls(addr_a, &probe_a, "bad-sig", port_a, Some(&fp_a))
            .await
            .expect_err("forged TLS signature must fail closed even if cert DER matches");
        assert!(
            matches!(err_a, RdpPrecheckError::TlsInvalid { .. }),
            "expected TlsInvalid for forged signature, got {err_a:?}"
        );
        pump_a.abort();
        srv_a.abort();

        // Subcase B: Server attempts TLS 1.0 (0x0301) ServerHello downgrade after X.224 CC.
        let upstream_b = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let port_b = upstream_b.local_addr().unwrap().port();
        let srv_b = tokio::spawn(async move {
            if let Ok((mut stream, _)) = upstream_b.accept().await {
                let mut req = [0u8; 19];
                let _ = stream.read_exact(&mut req).await;
                let _ = stream.write_all(&x224_cc_neg_rsp(X224_PROTOCOL_SSL)).await;
                // Read part of ClientHello, then emit a TLS 1.0 (0x03, 0x01) ServerHello record.
                let mut ch_hdr = [0u8; 5];
                let _ = stream.read_exact(&mut ch_hdr).await;
                let tls10_server_hello = [
                    0x16, 0x03, 0x01, 0x00, 0x2a, // Handshake record, TLS 1.0, len=42
                    0x02, 0x00, 0x00, 0x26, // ServerHello, len=38
                    0x03, 0x01, // server_version = TLS 1.0 (0x0301)
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, // random (32B)
                    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,    //
                    0x00, // session_id len = 0
                    0x00, 0x2f, // cipher_suite TLS_RSA_WITH_AES_128_CBC_SHA
                    0x00, // compression = null
                ];
                let _ = stream.write_all(&tls10_server_hello).await;
            }
        });
        let listener_b = bind_unique_session_loopback_listener().await.unwrap();
        let addr_b = listener_b.local_addr().unwrap();
        let (pump_b, probe_b) =
            spawn_rdp_loopback_tunnel_with_probe(listener_b, "127.0.0.1".into(), port_b, None);

        let err_b = precheck_rdp_tunnel_tls(addr_b, &probe_b, "tls10-host", port_b, None)
            .await
            .expect_err("TLS 1.0 downgrade must fail closed");
        assert!(
            matches!(err_b, RdpPrecheckError::TlsInvalid { .. }),
            "expected TlsInvalid for TLS 1.0 ServerHello, got {err_b:?}"
        );
        pump_b.abort();
        srv_b.abort();
    }

    #[tokio::test]
    async fn precheck_fails_closed_on_post_tcp_handshake_timeout() {
        let upstream = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let upstream_port = upstream.local_addr().unwrap().port();
        let srv_task = tokio::spawn(async move {
            if let Ok((_stalled_stream, _)) = upstream.accept().await {
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        });

        let listener = bind_unique_session_loopback_listener().await.unwrap();
        let local_addr = listener.local_addr().unwrap();
        let (pump, probe) = spawn_rdp_loopback_tunnel_with_probe(
            listener,
            "127.0.0.1".to_string(),
            upstream_port,
            None,
        );

        let err = precheck_rdp_tunnel_tls_with_timeout(
            local_addr,
            &probe,
            "stalled-rdp",
            upstream_port,
            None,
            Duration::from_millis(250),
        )
        .await
        .expect_err("post-TCP stall must time out fail-closed");
        assert!(
            matches!(err, RdpPrecheckError::Timeout { .. }),
            "expected Timeout, got {err:?}"
        );
        assert!(err.to_string().contains("超时"));

        pump.abort();
        srv_task.abort();
    }

    #[tokio::test]
    async fn precheck_fails_closed_when_target_port_or_socks5_mesh_is_unreachable() {
        // Subcase A: SOCKS5 proxy returns REP=0x04 (Host unreachable) when target daemon is offline.
        let socks_srv = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let socks_port = socks_srv.local_addr().unwrap().port();
        let srv_a = tokio::spawn(async move {
            while let Ok((mut s, _)) = socks_srv.accept().await {
                tokio::spawn(async move {
                    let mut greet = [0u8; 3];
                    let _ = s.read_exact(&mut greet).await;
                    let _ = s.write_all(&[0x05, 0x00]).await;
                    let mut head = [0u8; 5];
                    if s.read_exact(&mut head).await.is_ok() {
                        let dlen = head[4] as usize;
                        let mut rest = vec![0u8; dlen + 2];
                        let _ = s.read_exact(&mut rest).await;
                        // Reply REP=0x04 (Host unreachable)
                        let _ = s
                            .write_all(&[0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                            .await;
                    }
                });
            }
        });

        let listener_a = bind_unique_session_loopback_listener().await.unwrap();
        let addr_a = listener_a.local_addr().unwrap();
        let (pump_a, probe_a) = spawn_rdp_loopback_tunnel_with_probe(
            listener_a,
            "100.64.0.77".to_string(),
            3389,
            Some(socks_port),
        );

        let err_a = precheck_rdp_tunnel_tls(addr_a, &probe_a, "offline-box", 3389, None)
            .await
            .expect_err("offline SOCKS5 target must fail closed");
        assert!(
            matches!(err_a, RdpPrecheckError::Unreachable { .. }),
            "expected Unreachable, got {err_a:?}"
        );
        assert!(
            err_a.to_string().contains("经网格无法连到目标 RDP 端口"),
            "unexpected message: {err_a}"
        );

        let err_reach = precheck_rdp_tunnel_reachability(addr_a, &probe_a, "offline-box", 3389)
            .await
            .expect_err("reachability check on offline target must also fail closed");
        assert!(
            err_reach
                .to_string()
                .contains("经网格无法连到目标 RDP 端口"),
            "unexpected reachability error: {err_reach}"
        );
        pump_a.abort();
        srv_a.abort();

        // Subcase B: SOCKS5 proxy stalls during CONNECT (stopped remote WireGuard daemon
        // drops SYN packets silently) -> fails within timeout budget with `Unreachable`.
        let blackhole_socks = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let bh_port = blackhole_socks.local_addr().unwrap().port();
        let srv_b = tokio::spawn(async move {
            if let Ok((mut s, _)) = blackhole_socks.accept().await {
                let mut greet = [0u8; 3];
                let _ = s.read_exact(&mut greet).await;
                let _ = s.write_all(&[0x05, 0x00]).await;
                tokio::time::sleep(Duration::from_secs(2)).await;
            }
        });
        let listener_b = bind_unique_session_loopback_listener().await.unwrap();
        let addr_b = listener_b.local_addr().unwrap();
        let (pump_b, probe_b) = spawn_rdp_loopback_tunnel_with_probe(
            listener_b,
            "100.64.0.88".to_string(),
            3389,
            Some(bh_port),
        );
        let err_b = precheck_rdp_tunnel_tls_with_timeout(
            addr_b,
            &probe_b,
            "stopped-daemon-box",
            3389,
            None,
            Duration::from_millis(250),
        )
        .await
        .expect_err("blackholed mesh CONNECT must fail within budget");
        assert!(
            matches!(err_b, RdpPrecheckError::Unreachable { .. }),
            "expected Unreachable when upstream never connected, got {err_b:?}"
        );
        assert!(err_b.to_string().contains("经网格无法连到目标 RDP 端口"));
        pump_b.abort();
        srv_b.abort();
    }

    #[tokio::test]
    async fn session_loopback_listener_is_unique_127_77_on_windows_and_localhost_elsewhere() {
        let a = bind_unique_session_loopback_listener().await.unwrap();
        let b = bind_unique_session_loopback_listener().await.unwrap();
        let (sa, sb) = (a.local_addr().unwrap(), b.local_addr().unwrap());
        assert!(sa.ip().is_loopback() && sb.ip().is_loopback());
        assert_ne!(
            sa, sb,
            "two concurrent sessions must never share a listener"
        );
        if cfg!(windows) {
            for ip in [sa.ip(), sb.ip()] {
                match ip {
                    std::net::IpAddr::V4(v4) => assert_eq!(v4.octets()[..2], [127, 77]),
                    std::net::IpAddr::V6(_) => panic!("session loopback must be IPv4"),
                }
            }
            assert_ne!(
                sa.ip(),
                sb.ip(),
                "Windows TERMSRV/<ip> targets must stay unique per session"
            );
        } else {
            // macOS has only 127.0.0.1 on lo0; a 127.77.x.y bind would fail there.
            let localhost = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
            assert_eq!(sa.ip(), localhost);
            assert_eq!(sb.ip(), localhost);
        }
    }

    #[test]
    fn enrich_device_rdp_metadata_and_precedence_rules() {
        let server_fp = "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99";
        let cli_fp = "11:22:33:44:55:66:77:88:99:00:AA:BB:CC:DD:EE:FF:11:22:33:44:55:66:77:88:99:00:AA:BB:CC:DD:EE:FF";

        let mut dev = ResolvedRdpDevice {
            org_id: "66366f7a7230306d6c657231".into(),
            device_id: "node-surface-01".into(),
            device_name: "surface-pro".into(),
            ..Default::default()
        };
        let row = localapi::DeviceRowLite {
            kind: "agent".into(),
            id: "66366f7a7230306d6c657232".into(),
            name: "surface-pro".into(),
            overlay_ip: Some("100.64.0.12".into()),
            overlay_node_id: Some("node-surface-01".into()),
            rdp_available: Some(true),
            rdp_port: Some(13389),
            rdp_cert_sha256: Some(server_fp.into()),
            ..Default::default()
        };
        enrich_device_rdp_metadata(
            &mut dev,
            Some("66366f7a7230306d6c657232"),
            Some("100.64.0.12"),
            &[row],
        );
        assert_eq!(dev.rdp_available, Some(true));
        assert_eq!(dev.rdp_port, Some(13389));
        assert_eq!(
            dev.rdp_cert_sha256.as_deref(),
            Some(normalize_cert_sha256(server_fp).unwrap().as_str())
        );

        let default_opts = RdpCliOptions {
            target: "surface-pro".into(),
            port: 3389,
            explicit_port: None,
            ..Default::default()
        };
        assert_eq!(effective_rdp_port(&default_opts, &dev), 13389);
        assert_eq!(
            effective_pinned_cert_sha256(&default_opts, &dev)
                .unwrap()
                .as_deref(),
            Some(normalize_cert_sha256(server_fp).unwrap().as_str())
        );

        let override_opts = RdpCliOptions {
            target: "surface-pro".into(),
            port: 23389,
            explicit_port: Some(23389),
            cert_sha256: Some(cli_fp.into()),
            ..Default::default()
        };
        assert_eq!(effective_rdp_port(&override_opts, &dev), 23389);
        assert_eq!(
            effective_pinned_cert_sha256(&override_opts, &dev)
                .unwrap()
                .as_deref(),
            Some(normalize_cert_sha256(cli_fp).unwrap().as_str())
        );
    }
}
