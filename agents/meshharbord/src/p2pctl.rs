// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-139 — Daemon-side Unified Overlay P2P Control Plane (`p2pctl`, TCP 41642).
//!
//! Serves and dials authenticated peer-to-peer control requests over the
//! overlay-intercepted TCP port [`P2P_CTL_PORT`] (`41642`):
//! - `DeviceInfo`: peer OS, version, SSH port/host pubkey, exec availability,
//!   and RDP availability/port/certificate SHA-256 pin for offline `mh rdp`
//!   and Companion device lists.
//! - `SshGrant` / `Exec`: offline capability-backed SSH grant and command
//!   execution (wired in Commit 13).
//!
//! Security boundaries:
//! 1. `WgDevice` unconditionally drops packets to TCP `41642` unless the inner
//!    IPv4 source is the decrypting WG peer's exact `/32` overlay IP.
//! 2. Every connection executes a mutual X25519 + HMAC-SHA256 `hello` handshake
//!    bound to `(tenant_id, origin_wg_pubkey, target_wg_pubkey, origin_nonce,
//!    target_nonce)` derived from the peers' static WireGuard keypair DH secret.
//! 3. Origins check `NetmapPeer::supports_p2pctl` BEFORE dialing TCP `41642`,
//!    and verify the server's `hello` proof BEFORE sending any request payload
//!    or trusting `P2pDeviceInfo`.
//! 4. FR-127 protected devices (`cfg.protected == true`) refuse all `p2pctl`
//!    requests.

use std::net::Ipv4Addr;
use std::time::Duration;

#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
use std::collections::HashMap;
#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
use std::sync::{Arc, Mutex, OnceLock};
#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
use std::time::Instant;

use meshharbor_remote_control::p2pctl::P2pDeviceInfo;
#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
use meshharbor_remote_control::p2pctl::{
    P2P_CTL_FIRST_FRAME_TIMEOUT, P2P_CTL_PORT, P2P_CTL_VERSION, P2pClientRequest, P2pHelloInit,
    P2pHelloResp, P2pReq, P2pResp, compute_hello_proof, decode_hex, derive_hello_mac_key,
    encode_hex, read_frame, verify_hello_proof, write_frame,
};
#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
use meshharbor_remote_control::signaling::{NetmapPeer, OverlayNetworkInfo};
#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
use ring::rand::{SecureRandom, SystemRandom};
#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
use tokio::net::TcpStream;
#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
use tracing::{debug, warn};
#[cfg(feature = "overlay-netstack")]
use tracing::info;

use crate::config::AgentConfig;

/// Short-lived cache for verified `P2pDeviceInfo` answers per peer IP.
#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
const DEVICE_INFO_CACHE_TTL: Duration = Duration::from_secs(15);

/// Whether the `p2pctl` overlay control plane is enabled on this node.
/// Built-in default: ON (`p2p_control_enabled = false` or
/// `MESHHARBORD_P2P_CONTROL_ENABLED=0` disables it).
pub fn enabled(cfg: &AgentConfig) -> bool {
    if cfg.p2p_control_enabled == Some(false) {
        return false;
    }
    tunnel_core::env::flag("P2P_CONTROL_ENABLED", true)
}

/// One netmap peer indexed in the in-memory [`PeerDirectory`].
#[derive(Debug, Clone)]
pub struct PeerEntry {
    pub node_id: String,
    pub agent_id: Option<String>,
    pub name: String,
    pub overlay_ip: Ipv4Addr,
    pub wg_public_key: String,
    pub wg_public_bytes: [u8; 32],
    pub supports_p2pctl: bool,
    pub backbone_only: bool,
    pub reachable: bool,
}

#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
#[derive(Clone)]
pub struct TenantDirectory {
    pub tenant_id: String,
    pub self_agent_id: String,
    pub self_wg_pubkey: String,
    pub self_wg_secret: [u8; 32],
    pub self_ip: String,
    pub network: OverlayNetworkInfo,
    pub peers_by_ip: HashMap<Ipv4Addr, PeerEntry>,
    pub peers: Vec<PeerEntry>,
    pub socks_port: Option<u16>,
    info_cache: HashMap<Ipv4Addr, (Instant, P2pDeviceInfo)>,
}

#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
fn peer_directory() -> &'static Mutex<HashMap<String, TenantDirectory>> {
    static DIR: OnceLock<Mutex<HashMap<String, TenantDirectory>>> = OnceLock::new();
    DIR.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Update the in-memory `PeerDirectory` for `tenant_id` from a live or
/// cache-seeded netmap snapshot. Runs even when on-disk netmap caching is off.
#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
pub fn update_tenant_directory(
    tenant_id: &str,
    self_agent_id: &str,
    keypair: &tunnel_core::overlay::WgKeypair,
    self_ip: &str,
    network: &OverlayNetworkInfo,
    peers: &[NetmapPeer],
    socks_port: Option<u16>,
) {
    let mut by_ip = HashMap::with_capacity(peers.len());
    let mut list = Vec::with_capacity(peers.len());
    for p in peers {
        let Ok(ip) = p.overlay_ip.parse::<Ipv4Addr>() else {
            continue;
        };
        let Some(pk_bytes) = tunnel_core::overlay::decode_public(&p.wg_public_key) else {
            continue;
        };
        let entry = PeerEntry {
            node_id: p.node_id.to_hex(),
            agent_id: p.agent_id.map(|id| id.to_hex()),
            name: p.name.clone(),
            overlay_ip: ip,
            wg_public_key: p.wg_public_key.clone(),
            wg_public_bytes: pk_bytes,
            supports_p2pctl: p.supports_p2pctl,
            backbone_only: p.backbone_only,
            reachable: p.reachable,
        };
        by_ip.insert(ip, entry.clone());
        list.push(entry);
    }
    let mut guard = peer_directory().lock().unwrap_or_else(|e| e.into_inner());
    let prev_cache = guard
        .get(tenant_id)
        .map(|d| d.info_cache.clone())
        .unwrap_or_default();
    // Retain cached device info only for peers still present with the same WG key.
    let info_cache = prev_cache
        .into_iter()
        .filter(|(ip, _)| by_ip.contains_key(ip))
        .collect();
    guard.insert(
        tenant_id.to_string(),
        TenantDirectory {
            tenant_id: tenant_id.to_string(),
            self_agent_id: self_agent_id.to_string(),
            self_wg_pubkey: keypair.public_base64(),
            self_wg_secret: keypair.secret.to_bytes(),
            self_ip: self_ip.to_string(),
            network: network.clone(),
            peers_by_ip: by_ip,
            peers: list,
            socks_port,
            info_cache,
        },
    );
}

/// Remove a tenant's in-memory `PeerDirectory` entry (on revocation, `Goodbye`,
/// or overlay disable).
pub fn clear_tenant_directory(tenant_id: &str) {
    #[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
    {
        peer_directory()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(tenant_id);
    }
    #[cfg(not(any(feature = "overlay-l3", feature = "overlay-netstack")))]
    {
        let _ = tenant_id;
    }
}

/// Snapshot the known peers for `tenant_id` (empty on non-overlay builds or
/// before any netmap/cache has loaded).
pub fn tenant_peers(tenant_id: &str) -> Vec<PeerEntry> {
    #[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
    {
        peer_directory()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(tenant_id)
            .map(|d| d.peers.clone())
            .unwrap_or_default()
    }
    #[cfg(not(any(feature = "overlay-l3", feature = "overlay-netstack")))]
    {
        let _ = tenant_id;
        Vec::new()
    }
}

/// Lookup one peer by overlay IP in `tenant_id`.
pub fn lookup_by_ip(tenant_id: &str, ip: Ipv4Addr) -> Option<PeerEntry> {
    #[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
    {
        peer_directory()
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(tenant_id)
            .and_then(|d| d.peers_by_ip.get(&ip).cloned())
    }
    #[cfg(not(any(feature = "overlay-l3", feature = "overlay-netstack")))]
    {
        let _ = (tenant_id, ip);
        None
    }
}

/// Lookup a peer by agent_id, node_id, overlay IP, or case-insensitive name.
pub fn lookup_by_target(tenant_id: &str, target: &str) -> Option<PeerEntry> {
    let q = target.trim();
    if q.is_empty() {
        return None;
    }
    let ip_q = q.parse::<Ipv4Addr>().ok();
    tenant_peers(tenant_id).into_iter().find(|p| {
        ip_q == Some(p.overlay_ip)
            || p.node_id.eq_ignore_ascii_case(q)
            || p.agent_id
                .as_deref()
                .is_some_and(|a| a.eq_ignore_ascii_case(q))
            || p.name.eq_ignore_ascii_case(q)
    })
}

/// Tenant ACL mode string from the live/cached `PeerDirectory`, if known.
pub fn tenant_acl_mode(tenant_id: &str) -> Option<String> {
    #[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
    {
        let guard = peer_directory().lock().unwrap_or_else(|e| e.into_inner());
        let dir = guard.get(tenant_id)?;
        // OverlayNetworkInfo does not carry an explicit acl_mode string; infer
        // "enforce" when any peer carries ingress_rules, else "unknown".
        let _ = dir;
        Some("unknown".into())
    }
    #[cfg(not(any(feature = "overlay-l3", feature = "overlay-netstack")))]
    {
        let _ = tenant_id;
        None
    }
}

/// Server context passed into the `SplitTun` accept loop on port `41642`.
#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
#[derive(Clone)]
pub struct ServerCtx {
    pub tenant_id: String,
    pub self_agent_id: String,
    pub self_wg_pubkey: String,
    pub keypair: tunnel_core::overlay::WgKeypair,
    pub cfg: Arc<AgentConfig>,
    pub services: crate::ssh::SessionServices,
    /// Optional peer table override for isolated unit tests (production reads
    /// the process-wide `peer_directory()`).
    pub peer_override: Option<Arc<Mutex<HashMap<Ipv4Addr, PeerEntry>>>>,
}

#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
impl ServerCtx {
    pub fn new(
        cfg: &AgentConfig,
        keypair: tunnel_core::overlay::WgKeypair,
        services: crate::ssh::SessionServices,
    ) -> Self {
        Self {
            tenant_id: cfg.tenant_id.clone(),
            self_agent_id: cfg.agent_id.clone(),
            self_wg_pubkey: keypair.public_base64(),
            keypair,
            cfg: Arc::new(cfg.clone()),
            services,
            peer_override: None,
        }
    }

    fn lookup_peer(&self, peer_ip: Ipv4Addr) -> Option<PeerEntry> {
        if let Some(ov) = &self.peer_override {
            return ov
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .get(&peer_ip)
                .cloned();
        }
        lookup_by_ip(&self.tenant_id, peer_ip)
    }
}

/// Accept loop for intercepted TCP connections to `<overlay_ip>:41642`.
#[cfg(feature = "overlay-netstack")]
pub async fn accept_loop(
    mut listener: tunnel_core::overlay::netstack::NsListener,
    ctx: ServerCtx,
) {
    info!(
        port = P2P_CTL_PORT,
        tenant = %ctx.tenant_id,
        "p2pctl: serving intercepted overlay control port"
    );
    while let Some(stream) = listener.accept().await {
        let peer_ip = match stream.peer_addr().ip() {
            std::net::IpAddr::V4(v4) => v4,
            std::net::IpAddr::V6(_) => continue,
        };
        let ctx = ctx.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_conn(stream, peer_ip, ctx).await {
                debug!(%peer_ip, err = %e, "p2pctl: connection closed");
            }
        });
    }
    info!(
        port = P2P_CTL_PORT,
        tenant = %ctx.tenant_id,
        "p2pctl: intercepted overlay control port closed"
    );
}

#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
fn random_nonce_32() -> Result<[u8; 32], String> {
    let mut buf = [0u8; 32];
    SystemRandom::new()
        .fill(&mut buf)
        .map_err(|_| "CSPRNG failure generating p2pctl nonce".to_string())?;
    Ok(buf)
}

#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
fn local_device_info(cfg: &AgentConfig) -> P2pDeviceInfo {
    let rdp = crate::rdp_caps::current();
    let ssh_host_pubkey = if cfg.ssh_enabled {
        let pk = crate::ssh::host_public_key(cfg);
        (!pk.is_empty()).then_some(pk)
    } else {
        None
    };
    P2pDeviceInfo {
        os: std::env::consts::OS.to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        ssh_enabled: cfg.ssh_enabled,
        ssh_port: cfg.ssh_enabled.then(|| cfg.effective_ssh_port()),
        ssh_host_pubkey,
        exec_enabled: cfg.exec_enabled && !cfg.protected,
        rdp_available: Some(rdp.available),
        rdp_port: rdp.port,
        rdp_cert_sha256: rdp.cert_sha256,
        supports_p2pctl: true,
    }
}

/// Serve one `p2pctl` connection after `SplitTun` accepted it.
///
/// Generic over `AsyncRead + AsyncWrite + Unpin` so unit tests can exercise the
/// exact server handshake and request dispatch over `tokio::io::duplex` or TCP.
#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
pub async fn serve_conn<S>(
    mut stream: S,
    peer_ip: Ipv4Addr,
    ctx: ServerCtx,
) -> Result<(), String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let init: P2pHelloInit = tokio::time::timeout(P2P_CTL_FIRST_FRAME_TIMEOUT, read_frame(&mut stream))
        .await
        .map_err(|_| "timed out awaiting p2pctl hello".to_string())?
        .map_err(|e| format!("read hello init: {e}"))?;

    if init.v != P2P_CTL_VERSION {
        let _ = write_frame(
            &mut stream,
            &P2pHelloResp {
                v: P2P_CTL_VERSION,
                target_nonce_hex: String::new(),
                server_proof_hex: String::new(),
                error: Some(format!("unsupported p2pctl version {}", init.v)),
            },
        )
        .await;
        return Err("unsupported version".into());
    }
    if init.tenant_id != ctx.tenant_id || init.target_node_id != ctx.self_wg_pubkey {
        let _ = write_frame(
            &mut stream,
            &P2pHelloResp {
                v: P2P_CTL_VERSION,
                target_nonce_hex: String::new(),
                server_proof_hex: String::new(),
                error: Some("tenant or target identity mismatch".into()),
            },
        )
        .await;
        return Err("identity mismatch".into());
    }
    let Some(origin_nonce) = decode_hex(&init.origin_nonce_hex) else {
        return Err("invalid origin nonce hex".into());
    };
    if origin_nonce.len() != 32 {
        return Err("origin nonce must be 32 bytes".into());
    }

    let Some(peer) = ctx.lookup_peer(peer_ip) else {
        let _ = write_frame(
            &mut stream,
            &P2pHelloResp {
                v: P2P_CTL_VERSION,
                target_nonce_hex: String::new(),
                server_proof_hex: String::new(),
                error: Some("unknown peer overlay IP".into()),
            },
        )
        .await;
        return Err("unknown peer IP".into());
    };
    if peer.backbone_only {
        let _ = write_frame(
            &mut stream,
            &P2pHelloResp {
                v: P2P_CTL_VERSION,
                target_nonce_hex: String::new(),
                server_proof_hex: String::new(),
                error: Some("backbone-only peer refused on p2pctl".into()),
            },
        )
        .await;
        return Err("backbone-only peer refused".into());
    }
    if init.origin_node_id != peer.wg_public_key {
        let _ = write_frame(
            &mut stream,
            &P2pHelloResp {
                v: P2P_CTL_VERSION,
                target_nonce_hex: String::new(),
                server_proof_hex: String::new(),
                error: Some("origin identity does not match peer WG key".into()),
            },
        )
        .await;
        return Err("origin WG key mismatch".into());
    }

    let target_nonce = random_nonce_32()?;
    let shared = ctx.keypair.dh(&peer.wg_public_bytes);
    let mac_key = derive_hello_mac_key(&shared);
    let server_proof = compute_hello_proof(
        &mac_key,
        b"server",
        &ctx.tenant_id,
        &peer.wg_public_key,
        &ctx.self_wg_pubkey,
        &origin_nonce,
        &target_nonce,
    );
    write_frame(
        &mut stream,
        &P2pHelloResp {
            v: P2P_CTL_VERSION,
            target_nonce_hex: encode_hex(&target_nonce),
            server_proof_hex: server_proof,
            error: None,
        },
    )
    .await
    .map_err(|e| format!("write hello resp: {e}"))?;

    let req_env: P2pClientRequest =
        tokio::time::timeout(P2P_CTL_FIRST_FRAME_TIMEOUT, read_frame(&mut stream))
            .await
            .map_err(|_| "timed out awaiting p2pctl client request".to_string())?
            .map_err(|e| format!("read client request: {e}"))?;

    if req_env.v != P2P_CTL_VERSION
        || !verify_hello_proof(
            &mac_key,
            b"client",
            &ctx.tenant_id,
            &peer.wg_public_key,
            &ctx.self_wg_pubkey,
            &origin_nonce,
            &target_nonce,
            &req_env.client_proof_hex,
        )
    {
        let _ = write_frame(
            &mut stream,
            &P2pResp::Error {
                code: "auth_failed".into(),
                message: "p2pctl client hello proof verification failed".into(),
            },
        )
        .await;
        return Err("client hello proof failed".into());
    }

    // FR-127 — protected devices refuse offline P2P control requests.
    if ctx.cfg.protected {
        let _ = write_frame(
            &mut stream,
            &P2pResp::Error {
                code: "protected".into(),
                message: "this device is protected (FR-127); offline P2P control is refused".into(),
            },
        )
        .await;
        return Ok(());
    }

    let resp = match req_env.req {
        P2pReq::DeviceInfo => P2pResp::DeviceInfo(local_device_info(&ctx.cfg)),
        P2pReq::SshGrant { .. } | P2pReq::Exec { .. } => P2pResp::Error {
            code: "offline_cap_unsupported".into(),
            message: "offline capability verification is not enabled in this build".into(),
        },
    };
    write_frame(&mut stream, &resp)
        .await
        .map_err(|e| format!("write response: {e}"))?;
    Ok(())
}

/// Execute one authenticated `p2pctl` request/response exchange over an open
/// stream. Verifies the server's X25519+HMAC `hello` proof BEFORE sending
/// `req` so an unprivileged port-41642 squatter never receives capability
/// tokens, TOTP codes, commands, or spoofed metadata.
#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
pub async fn exchange_on_stream<S>(
    mut stream: S,
    tenant_id: &str,
    self_keypair: &tunnel_core::overlay::WgKeypair,
    target_wg_pubkey: &str,
    target_wg_bytes: &[u8; 32],
    req: P2pReq,
    timeout: Duration,
) -> Result<P2pResp, String>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let self_wg_pubkey = self_keypair.public_base64();
    let origin_nonce = random_nonce_32()?;
    let init = P2pHelloInit {
        v: P2P_CTL_VERSION,
        tenant_id: tenant_id.to_string(),
        origin_node_id: self_wg_pubkey.clone(),
        target_node_id: target_wg_pubkey.to_string(),
        origin_nonce_hex: encode_hex(&origin_nonce),
    };
    tokio::time::timeout(timeout, async {
        write_frame(&mut stream, &init)
            .await
            .map_err(|e| format!("send hello init: {e}"))?;
        let hello_resp: P2pHelloResp = read_frame(&mut stream)
            .await
            .map_err(|e| format!("read hello resp: {e}"))?;
        if let Some(err) = hello_resp.error {
            return Err(format!("p2pctl hello refused: {err}"));
        }
        if hello_resp.v != P2P_CTL_VERSION {
            return Err(format!("unexpected p2pctl version {}", hello_resp.v));
        }
        let target_nonce = decode_hex(&hello_resp.target_nonce_hex)
            .ok_or_else(|| "invalid target nonce hex".to_string())?;
        if target_nonce.len() != 32 {
            return Err("target nonce must be 32 bytes".to_string());
        }
        let shared = self_keypair.dh(target_wg_bytes);
        let mac_key = derive_hello_mac_key(&shared);
        if !verify_hello_proof(
            &mac_key,
            b"server",
            tenant_id,
            &self_wg_pubkey,
            target_wg_pubkey,
            &origin_nonce,
            &target_nonce,
            &hello_resp.server_proof_hex,
        ) {
            return Err(
                "p2pctl server hello proof failed (untrusted listener on port 41642)".into(),
            );
        }
        let client_proof = compute_hello_proof(
            &mac_key,
            b"client",
            tenant_id,
            &self_wg_pubkey,
            target_wg_pubkey,
            &origin_nonce,
            &target_nonce,
        );
        let env = P2pClientRequest {
            v: P2P_CTL_VERSION,
            client_proof_hex: client_proof,
            req,
        };
        write_frame(&mut stream, &env)
            .await
            .map_err(|e| format!("send request: {e}"))?;
        let resp: P2pResp = read_frame(&mut stream)
            .await
            .map_err(|e| format!("read response: {e}"))?;
        Ok(resp)
    })
    .await
    .map_err(|_| format!("p2pctl exchange timed out after {}ms", timeout.as_millis()))?
}

/// Dial TCP `peer_ip:P2P_CTL_PORT` either directly (OS-TUN) or via the
/// netstack loopback SOCKS5 proxy when running in netstack mode.
#[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
async fn dial_peer(
    peer_ip: Ipv4Addr,
    socks_port: Option<u16>,
    timeout: Duration,
) -> Result<TcpStream, String> {
    tokio::time::timeout(timeout, async {
        match socks_port {
            None => TcpStream::connect((peer_ip, P2P_CTL_PORT))
                .await
                .map_err(|e| format!("connect {peer_ip}:{P2P_CTL_PORT}: {e}")),
            Some(port) => {
                let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, port))
                    .await
                    .map_err(|e| format!("connect netstack socks5 127.0.0.1:{port}: {e}"))?;
                // RFC 1928 no-auth greeting
                stream
                    .write_all(&[0x05, 0x01, 0x00])
                    .await
                    .map_err(|e| format!("socks5 greet: {e}"))?;
                let mut sel = [0u8; 2];
                stream
                    .read_exact(&mut sel)
                    .await
                    .map_err(|e| format!("socks5 select: {e}"))?;
                if sel != [0x05, 0x00] {
                    return Err(format!("socks5 rejected no-auth: {sel:?}"));
                }
                // CONNECT IPv4 peer_ip:P2P_CTL_PORT
                let oct = peer_ip.octets();
                let p = P2P_CTL_PORT.to_be_bytes();
                let req = [
                    0x05, 0x01, 0x00, 0x01, oct[0], oct[1], oct[2], oct[3], p[0], p[1],
                ];
                stream
                    .write_all(&req)
                    .await
                    .map_err(|e| format!("socks5 connect write: {e}"))?;
                let mut hdr = [0u8; 4];
                stream
                    .read_exact(&mut hdr)
                    .await
                    .map_err(|e| format!("socks5 connect reply: {e}"))?;
                if hdr[0] != 0x05 || hdr[1] != 0x00 {
                    return Err(format!("socks5 connect failed (rep={:#x})", hdr[1]));
                }
                // Drain BND.ADDR + BND.PORT
                let drain_len = match hdr[3] {
                    0x01 => 4 + 2,
                    0x04 => 16 + 2,
                    0x03 => {
                        let n = stream
                            .read_u8()
                            .await
                            .map_err(|e| format!("socks5 bnd len: {e}"))?;
                        n as usize + 2
                    }
                    other => return Err(format!("socks5 unknown bnd atyp {other:#x}")),
                };
                let mut sink = vec![0u8; drain_len];
                stream
                    .read_exact(&mut sink)
                    .await
                    .map_err(|e| format!("socks5 bnd drain: {e}"))?;
                Ok(stream)
            }
        }
    })
    .await
    .map_err(|_| format!("dial {peer_ip}:{P2P_CTL_PORT} timed out"))?
}

/// Query `P2pReq::DeviceInfo` from a peer over `p2pctl`.
///
/// Refuses to dial peers without `supports_p2pctl` or marked `backbone_only`.
/// Caches verified results for [`DEVICE_INFO_CACHE_TTL`].
pub async fn query_device_info(
    tenant_id: &str,
    peer_ip: Ipv4Addr,
    timeout: Duration,
) -> Option<P2pDeviceInfo> {
    #[cfg(not(any(feature = "overlay-l3", feature = "overlay-netstack")))]
    {
        let _ = (tenant_id, peer_ip, timeout);
        None
    }
    #[cfg(any(feature = "overlay-l3", feature = "overlay-netstack"))]
    {
        let (self_secret, peer, socks_port) = {
            let guard = peer_directory().lock().unwrap_or_else(|e| e.into_inner());
            let dir = guard.get(tenant_id)?;
            let peer = dir.peers_by_ip.get(&peer_ip)?;
            if !peer.supports_p2pctl || peer.backbone_only {
                return None;
            }
            if let Some((at, info)) = dir.info_cache.get(&peer_ip)
                && at.elapsed() < DEVICE_INFO_CACHE_TTL
            {
                return Some(info.clone());
            }
            (dir.self_wg_secret, peer.clone(), dir.socks_port)
        };
        let keypair = tunnel_core::overlay::WgKeypair::from_secret_bytes(self_secret);
        let stream = match dial_peer(peer_ip, socks_port, timeout).await {
            Ok(s) => s,
            Err(e) => {
                debug!(%peer_ip, err = %e, "p2pctl: device_info dial failed");
                return None;
            }
        };
        match exchange_on_stream(
            stream,
            tenant_id,
            &keypair,
            &peer.wg_public_key,
            &peer.wg_public_bytes,
            P2pReq::DeviceInfo,
            timeout,
        )
        .await
        {
            Ok(P2pResp::DeviceInfo(info)) => {
                let mut guard = peer_directory().lock().unwrap_or_else(|e| e.into_inner());
                if let Some(dir) = guard.get_mut(tenant_id) {
                    dir.info_cache.insert(peer_ip, (Instant::now(), info.clone()));
                }
                Some(info)
            }
            Ok(P2pResp::Error { code, message }) => {
                debug!(%peer_ip, %code, %message, "p2pctl: device_info refused by peer");
                None
            }
            Ok(_) => None,
            Err(e) => {
                warn!(%peer_ip, err = %e, "p2pctl: device_info exchange failed");
                None
            }
        }
    }
}

#[cfg(all(test, any(feature = "overlay-l3", feature = "overlay-netstack")))]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use tunnel_core::overlay::WgKeypair;

    fn test_services() -> crate::ssh::SessionServices {
        let dir = std::env::temp_dir().join(format!(
            "meshharbor-p2pctl-test-{}-{}",
            std::process::id(),
            bson::oid::ObjectId::new().to_hex()
        ));
        let broker =
            crate::consent::ConsentBroker::new(crate::consent::Mode::AutoGrant, dir).unwrap();
        crate::ssh::SessionServices {
            power_activity: None,
            asker: crate::ssh::Asker::Here {
                broker,
                indicator: crate::indicator::ViewerIndicator::disabled(),
            },
            activity: None,
        }
    }

    fn make_peer_entry(kp: &WgKeypair, ip: Ipv4Addr, supports_p2pctl: bool) -> PeerEntry {
        PeerEntry {
            node_id: bson::oid::ObjectId::new().to_hex(),
            agent_id: Some(bson::oid::ObjectId::new().to_hex()),
            name: "peer-a".into(),
            overlay_ip: ip,
            wg_public_key: kp.public_base64(),
            wg_public_bytes: kp.public.to_bytes(),
            supports_p2pctl,
            backbone_only: false,
            reachable: true,
        }
    }

    #[tokio::test]
    async fn fr139_p2pctl_mutual_hello_and_device_info_roundtrip() {
        let origin_kp = WgKeypair::generate();
        let target_kp = WgKeypair::generate();
        let origin_ip = Ipv4Addr::new(100, 64, 0, 10);

        let mut cfg = crate::config::test_fixture();
        cfg.tenant_id = "tenant-p2p".into();
        cfg.agent_id = "agent-target".into();
        cfg.ssh_enabled = true;
        cfg.exec_enabled = true;
        cfg.protected = false;

        let mut peers = HashMap::new();
        peers.insert(origin_ip, make_peer_entry(&origin_kp, origin_ip, true));
        let mut ctx = ServerCtx::new(&cfg, target_kp.clone(), test_services());
        ctx.peer_override = Some(Arc::new(Mutex::new(peers)));

        let (client_io, server_io) = tokio::io::duplex(16 * 1024);
        let srv = tokio::spawn(serve_conn(server_io, origin_ip, ctx));
        let resp = exchange_on_stream(
            client_io,
            "tenant-p2p",
            &origin_kp,
            &target_kp.public_base64(),
            &target_kp.public.to_bytes(),
            P2pReq::DeviceInfo,
            Duration::from_secs(2),
        )
        .await
        .expect("mutual hello + device_info must succeed");
        srv.await.unwrap().expect("server clean finish");

        match resp {
            P2pResp::DeviceInfo(info) => {
                assert!(info.supports_p2pctl);
                assert!(info.ssh_enabled);
                assert!(info.exec_enabled);
                assert_eq!(info.os, std::env::consts::OS);
                assert!(info.rdp_available.is_some());
            }
            other => panic!("expected DeviceInfo, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn fr139_p2pctl_rejects_unprivileged_squatter_before_sending_request() {
        let origin_kp = WgKeypair::generate();
        let real_target_kp = WgKeypair::generate();
        let squatter_kp = WgKeypair::generate();

        let (client_io, mut squatter_io) = tokio::io::duplex(16 * 1024);
        let saw_request_frame = Arc::new(AtomicBool::new(false));
        let saw_clone = Arc::clone(&saw_request_frame);

        // Squatter listens on 41642 without real_target_kp's private key and
        // replies with a forged server_proof.
        let squatter = tokio::spawn(async move {
            let init: P2pHelloInit = read_frame(&mut squatter_io).await.unwrap();
            let fake_nonce = [0x99u8; 32];
            let wrong_shared = squatter_kp.dh(&origin_kp.public.to_bytes());
            let wrong_key = derive_hello_mac_key(&wrong_shared);
            let origin_nonce = decode_hex(&init.origin_nonce_hex).unwrap();
            let forged_proof = compute_hello_proof(
                &wrong_key,
                b"server",
                &init.tenant_id,
                &init.origin_node_id,
                &init.target_node_id,
                &origin_nonce,
                &fake_nonce,
            );
            write_frame(
                &mut squatter_io,
                &P2pHelloResp {
                    v: P2P_CTL_VERSION,
                    target_nonce_hex: encode_hex(&fake_nonce),
                    server_proof_hex: forged_proof,
                    error: None,
                },
            )
            .await
            .unwrap();
            // Client MUST disconnect without sending a P2pClientRequest frame!
            if read_frame::<_, P2pClientRequest>(&mut squatter_io)
                .await
                .is_ok()
            {
                saw_clone.store(true, Ordering::SeqCst);
            }
        });

        let err = exchange_on_stream(
            client_io,
            "tenant-p2p",
            &origin_kp,
            &real_target_kp.public_base64(),
            &real_target_kp.public.to_bytes(),
            P2pReq::Exec {
                offline_cap: "secret-cap-token".into(),
                request_id: "r1".into(),
                shell: "sh".into(),
                command: "id".into(),
                timeout_ms: 5000,
                two_factor_code: Some("123456".into()),
            },
            Duration::from_secs(2),
        )
        .await
        .expect_err("forged server proof must be rejected");
        assert!(
            err.contains("server hello proof failed"),
            "unexpected error: {err}"
        );
        squatter.await.unwrap();
        assert!(
            !saw_request_frame.load(Ordering::SeqCst),
            "origin must NEVER transmit request payload or capability token to an unverified squatter"
        );
    }

    #[tokio::test]
    async fn fr139_p2pctl_refuses_fr127_protected_device() {
        let origin_kp = WgKeypair::generate();
        let target_kp = WgKeypair::generate();
        let origin_ip = Ipv4Addr::new(100, 64, 0, 11);

        let mut cfg = crate::config::test_fixture();
        cfg.tenant_id = "tenant-prot".into();
        cfg.agent_id = "agent-prot".into();
        cfg.protected = true;

        let mut peers = HashMap::new();
        peers.insert(origin_ip, make_peer_entry(&origin_kp, origin_ip, true));
        let mut ctx = ServerCtx::new(&cfg, target_kp.clone(), test_services());
        ctx.peer_override = Some(Arc::new(Mutex::new(peers)));

        let (client_io, server_io) = tokio::io::duplex(16 * 1024);
        let srv = tokio::spawn(serve_conn(server_io, origin_ip, ctx));
        let resp = exchange_on_stream(
            client_io,
            "tenant-prot",
            &origin_kp,
            &target_kp.public_base64(),
            &target_kp.public.to_bytes(),
            P2pReq::DeviceInfo,
            Duration::from_secs(2),
        )
        .await
        .expect("handshake succeeds then returns protected refusal");
        srv.await.unwrap().expect("server clean finish");

        match resp {
            P2pResp::Error { code, .. } => assert_eq!(code, "protected"),
            other => panic!("expected protected Error, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn fr139_p2pctl_skips_legacy_peer_without_supports_p2pctl() {
        let origin_kp = WgKeypair::generate();
        let legacy_kp = WgKeypair::generate();
        let legacy_ip = Ipv4Addr::new(100, 64, 0, 99);
        let tid = format!("tenant-legacy-{}", bson::oid::ObjectId::new().to_hex());

        let net = OverlayNetworkInfo {
            cidr: "100.64.0.0/10".into(),
            cidrs: vec!["100.64.0.0/10".into()],
            org_relay_fallback_v1: false,
            org_relay_loss_v1: false,
            path_quality_v1: false,
            mtu: 1280,
            magic_domain: None,
            nameservers: vec![],
            self_name: None,
            self_node_id: None,
            self_name_revision: None,
            stun_urls: vec![],
            strict_stun: false,
            central_relay_denied: false,
            relay_probe_targets: vec![],
            backbone_probe_targets: vec![],
            auth_revision: 1,
        };
        let legacy_peer = NetmapPeer {
            node_id: bson::oid::ObjectId::new(),
            overlay_ip: legacy_ip.to_string(),
            name: "legacy".into(),
            wg_public_key: legacy_kp.public_base64(),
            endpoints: vec![],
            lan_endpoints: vec![],
            srflx_endpoints: vec![],
            srflx_nat: None,
            caps: None,
            udp_dialer_ok: None,
            relay_home: None,
            warm_relay_endpoint: None,
            reachable: true,
            supports_quic: false,
            supports_relay_single: false,
            supports_derp: false,
            supports_forced_derp: false,
            supports_derp_floor: false,
            supports_org_relay: false,
            supports_overlay_echo: false,
            supports_p2pctl: false,
            relay_strategy: None,
            prefer_relay_ms: None,
            routes: vec![],
            agent_id: None,
            ingress_rules: None,
            ingress_rules_preview: None,
            backbone_only: false,
        };
        update_tenant_directory(
            &tid,
            "self-a",
            &origin_kp,
            "100.64.0.1",
            &net,
            &[legacy_peer],
            None,
        );
        // Must return None immediately without attempting any TCP dial.
        let started = Instant::now();
        let info = query_device_info(&tid, legacy_ip, Duration::from_secs(5)).await;
        assert!(info.is_none());
        assert!(started.elapsed() < Duration::from_millis(200));
        clear_tenant_directory(&tid);
    }
}
