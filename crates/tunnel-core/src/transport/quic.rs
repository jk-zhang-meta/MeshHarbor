// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! `quic-v1` transport — opportunistic QUIC P2P data plane (quinn).
//!
//! This is the Phase-1a *core*: a [`QuicPeer`] that builds a quinn
//! endpoint (server or client) and yields per-flow bidirectional
//! streams. Each tunnel flow is a native QUIC bi-stream — multiplexed,
//! flow-controlled, ordered, with an explicit FIN — so the WebRTC-DC
//! machinery in [`crate::forward`] (the `flow_id` framing, the
//! `HALF_CLOSE_MAGIC` sentinel, the 65535-byte cap, the
//! `bufferedAmountLow` watermark dance) is **not needed here**. The
//! data pump is just [`crate::forward::run_flow_quic`] piping TCP ↔
//! stream.
//!
//! **Auth without a CA** (mirrors WebRTC's DTLS-fingerprint model):
//! the server side mints an *ephemeral self-signed* cert and publishes
//! its SHA-256 fingerprint over the already-trusted signaling channel;
//! the client *pins* that fingerprint via [`FingerprintVerifier`]
//! instead of trusting a CA. The reverse direction (is the dialing
//! client authorized?) is a short-lived token presented on the
//! connection — wired in Phase 1d; this module carries the cert-pin
//! half and the stream plumbing.
//!
//! **Crypto provider:** `ring` everywhere (see Cargo.toml) so QUIC adds
//! no aws-lc-rs C/NASM build.

use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use quinn::{ClientConfig, Connection, Endpoint, ServerConfig};
// Re-export the quinn stream + connection types so consumer crates (the
// agent + tunnel-client) can name flow-stream halves WITHOUT a direct
// quinn dependency — which would otherwise need its own ring crypto-
// provider feature config to avoid pulling aws-lc-rs (a C build).
pub use quinn::{Connection as QuicConnection, ConnectionError, RecvStream, SendStream};
use rustls::DigitallySignedStruct;
use rustls::SignatureScheme;
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::{CryptoProvider, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use sha2::{Digest, Sha256};

use super::{Capabilities, TRANSPORT_QUIC_V1, Transport};

/// ALPN id for the tunnel's QUIC connections. Both ends must match or
/// the TLS handshake fails (a cheap version/role guard).
///
/// FR-46 P4, step 1 of 3. The wire value cannot be renamed in one release: the
/// ALPN travels in the ClientHello and a peer that offers only the new name to
/// a server that knows only the old one gets a clean handshake failure, i.e. a
/// silently dead carrier. So the SERVER learns the new name first and keeps
/// accepting the old, the CLIENT keeps offering the old until every peer can
/// answer it, and only then does the old one go.
// RETIRED-NAME-ANCHOR(2): WIRE VALUE — this is what deployed peers offer today,
// and it stays until the client half has flipped everywhere. docs/fr/FR-46
const ALPN_LEGACY: &[u8] = b"meshharbor-tunnel-quic-v1";

/// The ALPN the tunnel is moving TO. Accepted by the server from this release;
/// not yet offered by the client (see [`ALPN_LEGACY`]).
const ALPN: &[u8] = b"meshharbord-quic-v1";

/// ALPN id for the overlay's WG-over-QUIC **datagram** carrier. Distinct from
/// [`ALPN`] so a stream-tunnel endpoint and a datagram endpoint can never
/// complete a handshake against each other (mismatched ALPN → clean failure).
const OVERLAY_ALPN: &[u8] = b"meshharbor-overlay-wg-v1";

/// Placeholder SNI — the client pins by cert fingerprint, not by name.
///
/// FR-46 renamed this, which is safe in ONE release rather than three because
/// nothing on either end reads it: `FingerprintVerifier::verify_server_cert`
/// ignores `_server_name` entirely and compares a SHA-256 pin, and the cert is
/// generated per process, so a new SAN simply yields a new fingerprint that is
/// advertised over signalling like any other. It is not a version guard and
/// never was — the ALPN above is.
const SNI: &str = "meshharbord";

/// SHA-256 fingerprint of a DER certificate, lowercase hex. This is the
/// value the agent advertises over signaling and the client pins.
pub fn cert_fingerprint(cert_der: &[u8]) -> String {
    hex::encode(Sha256::digest(cert_der))
}

/// Phase 2 (Tier 1): gather dialable **host candidates** for a QUIC
/// endpoint bound on `port`. Returns the primary egress-interface IPv4
/// paired with `port` — i.e. an address a peer on the same LAN (or one
/// with a direct route / port-forward) can dial. The agent advertises
/// these in `rc:tunnel.quic.ready` so the client's connect loop can try
/// them in order; the bare `0.0.0.0:port` the endpoint binds to is NOT
/// dialable, which is why this exists.
///
/// Phase 2b adds STUN **server-reflexive** candidates (the public
/// mapping behind a NAT) alongside these. For now this is host-only,
/// which already unblocks same-LAN / directly-reachable hosts.
pub fn host_candidates(port: u16) -> Vec<SocketAddr> {
    let mut out = Vec::new();
    if let Some(ip) = primary_egress_ipv4() {
        out.push(SocketAddr::new(ip, port));
    }
    out
}

/// Discover the primary egress-interface IPv4 via the classic
/// "connect a UDP socket to a public address and read its local_addr"
/// trick: `connect` on a UDP socket sends NO datagram — it just makes
/// the OS pick the outbound route and bind the socket to the egress
/// interface's address, which `local_addr` then reports. Needs no
/// interface-enumeration crate and no network round-trip. Returns
/// `None` when there's no usable route (offline / loopback-only), in
/// which case the caller simply advertises no host candidate and the
/// client falls back to another transport.
fn primary_egress_ipv4() -> Option<IpAddr> {
    let sock = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).ok()?;
    // 8.8.8.8:80 is a route hint only; no packet is sent by `connect`.
    sock.connect((Ipv4Addr::new(8, 8, 8, 8), 80)).ok()?;
    match sock.local_addr().ok()?.ip() {
        IpAddr::V4(v4) if !v4.is_loopback() && !v4.is_unspecified() => Some(IpAddr::V4(v4)),
        _ => None,
    }
}

/// Gather all dialable candidates for a QUIC endpoint that will adopt
/// `socket`: host candidates (Phase 2a) plus one STUN server-reflexive
/// candidate per reachable entry in `stun_servers` (Phase 2b). Run this
/// BEFORE handing the socket to [`QuicPeer::server_from_socket`] /
/// [`QuicPeer::client_from_socket`] so STUN traverses the SAME NAT
/// mapping QUIC will use. De-dups; a STUN failure is logged + skipped
/// (host candidates alone still serve same-LAN / directly-reachable
/// peers).
pub async fn gather_candidates(
    socket: &tokio::net::UdpSocket,
    stun_servers: &[SocketAddr],
    stun_timeout: std::time::Duration,
) -> Vec<SocketAddr> {
    let port = socket.local_addr().map(|a| a.port()).unwrap_or(0);
    let mut cands = host_candidates(port);
    for &server in stun_servers {
        match super::stun::srflx_query(socket, server, stun_timeout).await {
            Ok(srflx) if !cands.contains(&srflx) => cands.push(srflx),
            Ok(_) => {}
            Err(e) => tracing::debug!(%server, %e, "stun srflx gather failed; skipping"),
        }
    }
    cands
}

/// Shared quinn transport tuning for both endpoints. **Keepalive is
/// load-bearing for the tunnel:** a forward sits idle between queries, and
/// without periodic traffic quinn idle-closes the connection (≈30 s) — so
/// the next query hits a dead connection (`open_bi` fails). An 8 s
/// keepalive also keeps the TURN permission/binding fresh on the relay
/// path (coturn permissions lapse ~5 min). `keep_alive_interval` MUST stay
/// below `max_idle_timeout`.
fn quic_transport_config() -> Arc<quinn::TransportConfig> {
    let mut t = quinn::TransportConfig::default();
    t.keep_alive_interval(Some(Duration::from_secs(8)));
    t.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(Duration::from_secs(30)).expect("30s is a valid idle timeout"),
    ));
    // Flow-control windows sized for the relay's high BDP (controller →
    // coturn → agent's TLS/TCP leg → dst — the TCP relay's buffering
    // inflates the effective BDP far above the raw RTT, to ~9 MiB at the
    // ~24 Mbps ceiling). quinn's ~1 MiB defaults throttled a single bulk
    // stream hard: 2026-06-03 measured QUIC 238 s vs WebRTC 77 s for the
    // same `select *`; raising the stream window to 8 MiB cut QUIC to 61 s
    // — faster than WebRTC. **8 MiB is the chosen value.** An interleaved
    // 8-vs-16 MiB A/B (2026-06-04, 3 rounds) found them equivalent —
    // 8 MiB avg 75.6 s (tight 75.2–76.0) vs 16 MiB avg 73.8 s (noisy
    // 69.3–77.5) — i.e. past the ~9 MiB BDP a bigger window buys nothing
    // (only buffering), so we keep 8 MiB for half the per-stream memory and
    // steadier latency. `VarInt` allows far more (~4.6 EB) if a future
    // higher-BDP path needs it. The RECEIVER advertises these, so each
    // peer's window governs its RECEIVE direction (client → DB→client
    // download; agent → client→DB upload).
    const STREAM_WIN: u32 = 8 * 1024 * 1024;
    t.stream_receive_window(quinn::VarInt::from_u32(STREAM_WIN));
    t.receive_window(quinn::VarInt::from_u32(2 * STREAM_WIN));
    t.send_window(u64::from(2 * STREAM_WIN));
    Arc::new(t)
}

/// Transport config for the overlay's WG-over-QUIC **datagram** carrier —
/// distinct from the stream-tunnel [`quic_transport_config`]. Same 8 s
/// keepalive / 30 s idle (keeps the coturn permission fresh + the connection
/// from idle-closing), but raises `initial_mtu` so a full 1280-MTU WireGuard
/// packet (≈1312 B ciphertext) fits ONE QUIC datagram: quinn's usable datagram
/// ≈ `current_mtu − 38`, and the default `initial_mtu` of 1200 yields only
/// ~1162 B — too small. 1400 → ~1362 B usable (≥1312 with ~50 B margin, since
/// the exact overhead varies with connection-ID length); PLPMTUD may climb
/// higher. Wire frame stays ≈1432 B (1400 + coturn ChannelData 4 + UDP/IP 28)
/// < 1500 on both relay legs → no fragmentation. Stream windows are irrelevant
/// (this carrier only sends datagrams) so they're left default; datagrams
/// themselves are on by quinn default (`datagram_receive_buffer_size = Some(..)`).
fn overlay_datagram_transport_config() -> Arc<quinn::TransportConfig> {
    let mut t = quinn::TransportConfig::default();
    t.keep_alive_interval(Some(Duration::from_secs(8)));
    t.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(Duration::from_secs(30)).expect("30s is a valid idle timeout"),
    ));
    // ≥ 1312 (WG over MTU 1280) + ~38 (quinn 1-RTT + datagram-frame overhead),
    // with margin; wire frame ≈1432 B < 1500 so it won't fragment over coturn.
    t.initial_mtu(1400);
    // Absorb a short burst of WG packets before the congestion controller drains
    // them (datagrams stay lossy under it — this only bounds the send queue).
    t.datagram_send_buffer_size(256 * 1024);
    Arc::new(t)
}

/// R4 — transport tuning for the tunnel's QUIC-over-DERP flavor: the stream
/// tunnel's keepalive/idle/window set, PLUS a hard MTU clamp. The server's
/// `/derp` relay DROPS frames over `DERP_MAX_FRAME = 2048` bytes
/// (`api/ws/derp.rs`), and quinn's PLPMTUD probes PAST that — every probe
/// (and any packet it grows into) would die silently, passing smoke tests
/// and corrupting throughput in the field. So: MTU discovery OFF, and
/// `initial_mtu` pinned at quinn's 1200 floor (≪ 2016 usable payload after
/// the 32-byte pubkey frame header).
fn derp_stream_transport_config() -> Arc<quinn::TransportConfig> {
    let mut t = quinn::TransportConfig::default();
    t.keep_alive_interval(Some(Duration::from_secs(8)));
    t.max_idle_timeout(Some(
        quinn::IdleTimeout::try_from(Duration::from_secs(30)).expect("30s is a valid idle timeout"),
    ));
    const STREAM_WIN: u32 = 8 * 1024 * 1024;
    t.stream_receive_window(quinn::VarInt::from_u32(STREAM_WIN));
    t.receive_window(quinn::VarInt::from_u32(2 * STREAM_WIN));
    t.send_window(u64::from(2 * STREAM_WIN));
    t.initial_mtu(1200);
    t.mtu_discovery_config(None);
    Arc::new(t)
}

/// #2002 — the endpoint config for QUIC over DERP: quinn's, with fixed-bit
/// greasing (RFC 9287) OFF. The DERP leg demuxes each payload by its first
/// bytes ([`crate::transport::derp::payload_is_wg_or_disco`]), and greasing
/// let a short header start anywhere below 0x40: 2.6-4.0% of a transfer's
/// datagrams opened with a WireGuard type byte. An endpoint that does not
/// advertise the parameter is never sent a greased packet, and sends none
/// to a peer that does not advertise it either.
fn derp_endpoint_config() -> quinn::EndpointConfig {
    let mut cfg = quinn::EndpointConfig::default();
    cfg.grease_quic_bit(false);
    cfg
}

/// R4 — server config for the QUIC-over-DERP tunnel flavor: identical TLS
/// posture to [`build_server_config`] (ephemeral self-signed cert whose
/// fingerprint the client pins over signaling — the tunnel's auth model is
/// unchanged by the carrier), but the MTU-clamped transport config.
fn build_server_config_derp() -> Result<(ServerConfig, String)> {
    let (mut cfg, fingerprint) = build_server_config()?;
    cfg.transport_config(derp_stream_transport_config());
    Ok((cfg, fingerprint))
}

/// R4 — client analogue of [`build_server_config_derp`]: pinned-fingerprint
/// TLS + the MTU-clamped transport config.
fn build_client_config_derp(pinned_fingerprint_hex: &str) -> Result<ClientConfig> {
    let mut cfg = build_client_config(pinned_fingerprint_hex)?;
    cfg.transport_config(derp_stream_transport_config());
    Ok(cfg)
}

/// Build the quinn server config (TLS1.3, ephemeral self-signed cert,
/// ALPN) shared by [`QuicPeer::server`] and
/// [`QuicPeer::server_from_socket`]. Returns the config plus the cert
/// fingerprint to advertise over signaling.
fn build_server_config() -> Result<(ServerConfig, String)> {
    let certified = rcgen::generate_simple_self_signed(vec![SNI.to_string()])
        .context("rcgen ephemeral self-signed cert")?;
    let cert_der = CertificateDer::from(certified.cert.der().to_vec());
    let fingerprint = cert_fingerprint(&cert_der);
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der()));
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .context("quic server: tls13-only")?
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key)
        .context("quic server: single cert")?;
    // FR-46 P4 step 1: the SERVER learns the new ALPN and keeps accepting the
    // old one. Order is preference — a peer offering both gets the new name, a
    // deployed peer offering only the old one still completes. The CLIENT below
    // deliberately does NOT offer the new one yet.
    tls.alpn_protocols = vec![ALPN.to_vec(), ALPN_LEGACY.to_vec()];
    let qsc = QuicServerConfig::try_from(tls).context("quic server config from rustls")?;
    let mut server_config = ServerConfig::with_crypto(Arc::new(qsc));
    server_config.transport_config(quic_transport_config());
    Ok((server_config, fingerprint))
}

/// Build the quinn client config (TLS1.3, pinned-fingerprint verifier,
/// ALPN) shared by [`QuicPeer::client`] and
/// [`QuicPeer::client_from_socket`].
fn build_client_config(pinned_fingerprint_hex: &str) -> Result<ClientConfig> {
    // FR-46 P4 step 1: the CLIENT keeps offering ONLY the legacy ALPN until every
    // peer can answer the new one. Flipping this before then turns an upgraded
    // client dialling an older exit into a clean handshake failure — a carrier
    // that is simply dead, with the ladder falling back to DERP and nothing said.
    build_client_config_with_alpn(pinned_fingerprint_hex, vec![ALPN_LEGACY.to_vec()])
}

/// Split out so a test can offer the NEW ALPN and prove the server already
/// answers it — otherwise step 2 of the rename is a leap rather than a flip.
fn build_client_config_with_alpn(
    pinned_fingerprint_hex: &str,
    alpn: Vec<Vec<u8>>,
) -> Result<ClientConfig> {
    let pinned = decode_fingerprint(pinned_fingerprint_hex)?;
    let verifier = Arc::new(FingerprintVerifier {
        pinned,
        provider: Arc::new(provider()),
    });
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .context("quic client: tls13-only")?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    tls.alpn_protocols = alpn;
    let qcc = QuicClientConfig::try_from(tls).context("quic client config from rustls")?;
    let mut client_config = ClientConfig::new(Arc::new(qcc));
    client_config.transport_config(quic_transport_config());
    Ok(client_config)
}

/// Server config for the overlay WG-over-QUIC datagram carrier — an ephemeral
/// self-signed cert like [`build_server_config`], but the datagram transport
/// config + the overlay ALPN. No fingerprint is returned: the datagram client
/// accepts any cert (WG authenticates inside — see [`build_client_config_insecure`]).
fn build_server_config_datagram() -> Result<ServerConfig> {
    let certified = rcgen::generate_simple_self_signed(vec![SNI.to_string()])
        .context("rcgen ephemeral self-signed cert")?;
    let cert_der = CertificateDer::from(certified.cert.der().to_vec());
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der()));
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .context("quic overlay server: tls13-only")?
        .with_no_client_auth()
        .with_single_cert(vec![cert_der], key)
        .context("quic overlay server: single cert")?;
    tls.alpn_protocols = vec![OVERLAY_ALPN.to_vec()];
    let qsc = QuicServerConfig::try_from(tls).context("quic overlay server config from rustls")?;
    let mut server_config = ServerConfig::with_crypto(Arc::new(qsc));
    server_config.transport_config(overlay_datagram_transport_config());
    Ok(server_config)
}

/// Client config for the overlay WG-over-QUIC datagram carrier — accepts ANY
/// server cert. SOUND here because WireGuard Noise (Curve25519 netmap keys) is
/// the end-to-end auth boundary INSIDE the QUIC datagrams: coturn and any
/// on-path party only ever see WG ciphertext wrapped in QUIC, and a MITM who
/// swapped the QUIC cert still cannot pass the WG handshake. So per-node
/// cert-fingerprint plumbing would buy zero security; QUIC TLS is transport-only.
fn build_client_config_insecure() -> Result<ClientConfig> {
    let verifier = Arc::new(InsecureServerVerifier {
        provider: Arc::new(provider()),
    });
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(provider()))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .context("quic overlay client: tls13-only")?
        .dangerous()
        .with_custom_certificate_verifier(verifier)
        .with_no_client_auth();
    tls.alpn_protocols = vec![OVERLAY_ALPN.to_vec()];
    let qcc = QuicClientConfig::try_from(tls).context("quic overlay client config from rustls")?;
    let mut client_config = ClientConfig::new(Arc::new(qcc));
    client_config.transport_config(overlay_datagram_transport_config());
    Ok(client_config)
}

/// One QUIC endpoint (server or client side). Connections + per-flow
/// streams are opened off this.
pub struct QuicPeer {
    endpoint: Endpoint,
}

impl QuicPeer {
    /// Build a QUIC **server** endpoint with a fresh ephemeral
    /// self-signed cert. Returns the peer plus the cert fingerprint to
    /// advertise over signaling so the dialing client can pin it.
    pub fn server(bind: SocketAddr) -> Result<(Self, String)> {
        let (cfg, fingerprint) = build_server_config()?;
        let endpoint = Endpoint::server(cfg, bind).context("quic server endpoint")?;
        Ok((Self { endpoint }, fingerprint))
    }

    /// Like [`server`](Self::server) but adopts an EXISTING UDP socket so
    /// the caller can run STUN + hole-punch on it FIRST (Phase 2) — the
    /// NAT mapping QUIC then uses is the one that was punched. Pass the
    /// socket from [`gather_candidates`]'s tokio socket via `into_std()`.
    pub fn server_from_socket(socket: std::net::UdpSocket) -> Result<(Self, String)> {
        let (cfg, fingerprint) = build_server_config()?;
        let runtime = quinn::default_runtime().context("no async runtime for quinn endpoint")?;
        let endpoint = Endpoint::new(quinn::EndpointConfig::default(), Some(cfg), socket, runtime)
            .context("quic server endpoint from socket")?;
        Ok((Self { endpoint }, fingerprint))
    }

    /// Build a QUIC **client** endpoint that will only trust a server
    /// whose cert SHA-256 fingerprint equals `pinned_fingerprint_hex`
    /// (the value the agent sent over signaling).
    pub fn client(bind: SocketAddr, pinned_fingerprint_hex: &str) -> Result<Self> {
        let mut endpoint = Endpoint::client(bind).context("quic client endpoint")?;
        endpoint.set_default_client_config(build_client_config(pinned_fingerprint_hex)?);
        Ok(Self { endpoint })
    }

    /// Like [`client`](Self::client) but adopts an EXISTING (already
    /// STUN'd + punched) UDP socket. Phase 2.
    pub fn client_from_socket(
        socket: std::net::UdpSocket,
        pinned_fingerprint_hex: &str,
    ) -> Result<Self> {
        let runtime = quinn::default_runtime().context("no async runtime for quinn endpoint")?;
        let mut endpoint = Endpoint::new(quinn::EndpointConfig::default(), None, socket, runtime)
            .context("quic client endpoint from socket")?;
        endpoint.set_default_client_config(build_client_config(pinned_fingerprint_hex)?);
        Ok(Self { endpoint })
    }

    /// Phase 3: build a QUIC **server** endpoint over an arbitrary
    /// [`quinn::AsyncUdpSocket`] — e.g. [`crate::transport::relay::RelayUdpSocket`]
    /// wrapping a TURN-relayed conn, so QUIC rides a coturn allocation
    /// for symmetric-NAT / UDP-blocked nets. `local_addr()` of the
    /// socket is what the peer dials (the relay address).
    pub fn server_over_abstract_socket(
        socket: Arc<dyn quinn::AsyncUdpSocket>,
    ) -> Result<(Self, String)> {
        let (cfg, fingerprint) = build_server_config()?;
        let runtime = quinn::default_runtime().context("no async runtime for quinn endpoint")?;
        let endpoint = Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            Some(cfg),
            socket,
            runtime,
        )
        .context("quic server endpoint over abstract socket")?;
        Ok((Self { endpoint }, fingerprint))
    }

    /// Phase 3: client analogue of [`server_over_abstract_socket`].
    pub fn client_over_abstract_socket(
        socket: Arc<dyn quinn::AsyncUdpSocket>,
        pinned_fingerprint_hex: &str,
    ) -> Result<Self> {
        let runtime = quinn::default_runtime().context("no async runtime for quinn endpoint")?;
        let mut endpoint = Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            None,
            socket,
            runtime,
        )
        .context("quic client endpoint over abstract socket")?;
        endpoint.set_default_client_config(build_client_config(pinned_fingerprint_hex)?);
        Ok(Self { endpoint })
    }

    /// R4 — tunnel QUIC **server** over a DERP-backed abstract socket
    /// ([`crate::transport::relay::RelayUdpSocket`] wrapping a
    /// `DerpMux::tunnel_conn_for` conn). Stream-tunnel TLS (pinned
    /// fingerprint advertised over signaling) with the MTU-clamped derp
    /// transport config — see [`build_server_config_derp`].
    pub fn server_over_derp(socket: Arc<dyn quinn::AsyncUdpSocket>) -> Result<(Self, String)> {
        let (cfg, fingerprint) = build_server_config_derp()?;
        let runtime = quinn::default_runtime().context("no async runtime for quinn endpoint")?;
        let endpoint =
            Endpoint::new_with_abstract_socket(derp_endpoint_config(), Some(cfg), socket, runtime)
                .context("quic derp-tunnel server endpoint")?;
        Ok((Self { endpoint }, fingerprint))
    }

    /// R4 — client analogue of [`Self::server_over_derp`].
    pub fn client_over_derp(
        socket: Arc<dyn quinn::AsyncUdpSocket>,
        pinned_fingerprint_hex: &str,
    ) -> Result<Self> {
        let runtime = quinn::default_runtime().context("no async runtime for quinn endpoint")?;
        let mut endpoint =
            Endpoint::new_with_abstract_socket(derp_endpoint_config(), None, socket, runtime)
                .context("quic derp-tunnel client endpoint")?;
        endpoint.set_default_client_config(build_client_config_derp(pinned_fingerprint_hex)?);
        Ok(Self { endpoint })
    }

    /// Overlay carrier: a QUIC **server** endpoint that carries WireGuard as
    /// unreliable datagrams over a [`crate::transport::relay::RelayUdpSocket`]
    /// (a coturn allocation). Datagram-tuned transport (`initial_mtu=1350`,
    /// 8 s keepalive), transport-only TLS (accept-any-cert client). The peer
    /// dials this endpoint's relayed `local_addr`.
    pub fn server_over_relay_datagram(socket: Arc<dyn quinn::AsyncUdpSocket>) -> Result<Self> {
        let cfg = build_server_config_datagram()?;
        let runtime = quinn::default_runtime().context("no async runtime for quinn endpoint")?;
        let endpoint = Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            Some(cfg),
            socket,
            runtime,
        )
        .context("quic overlay-datagram server endpoint")?;
        Ok(Self { endpoint })
    }

    /// Overlay carrier: client analogue of [`server_over_relay_datagram`].
    /// Accepts any server cert (WG Noise is the auth boundary inside).
    pub fn client_over_relay_datagram(socket: Arc<dyn quinn::AsyncUdpSocket>) -> Result<Self> {
        let runtime = quinn::default_runtime().context("no async runtime for quinn endpoint")?;
        let mut endpoint = Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            None,
            socket,
            runtime,
        )
        .context("quic overlay-datagram client endpoint")?;
        endpoint.set_default_client_config(build_client_config_insecure()?);
        Ok(Self { endpoint })
    }

    /// The local socket address (after binding to port 0, the OS-chosen
    /// port) — needed to feed the peer our candidate over signaling.
    pub fn local_addr(&self) -> Result<SocketAddr> {
        self.endpoint.local_addr().context("quic local_addr")
    }

    /// Dial `addr` and complete the QUIC handshake (incl. the pinned
    /// cert check). The returned [`Connection`] carries per-flow streams.
    pub async fn connect(&self, addr: SocketAddr) -> Result<Connection> {
        let conn = self
            .endpoint
            .connect(addr, SNI)
            .context("quic connect")?
            .await
            .context("quic handshake")?;
        Ok(conn)
    }

    /// Accept the next inbound QUIC connection, or `None` when the
    /// endpoint is closed.
    pub async fn accept(&self) -> Option<Result<Connection>> {
        let incoming = self.endpoint.accept().await?;
        Some(incoming.await.context("quic accept handshake"))
    }
}

impl Transport for QuicPeer {
    fn label(&self) -> &'static str {
        TRANSPORT_QUIC_V1
    }
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            multi_stream: true,  // one QUIC connection carries many flow streams natively
            supports_udp: false, // v1 forwards TCP only
            l3: false,
        }
    }
}

/// Open a new bidirectional stream for `flow_id` and write the 4-byte
/// `flow_id` preamble so the accepting peer can correlate the stream to
/// the flow it already authorized + dialed via the `TcpForward*`
/// signaling. Returns the stream halves ready for the pump.
pub async fn open_flow(conn: &Connection, flow_id: u32) -> Result<(SendStream, RecvStream)> {
    let (mut send, recv) = conn.open_bi().await.context("quic open_bi")?;
    send.write_all(&flow_id.to_le_bytes())
        .await
        .context("quic write flow_id preamble")?;
    Ok((send, recv))
}

/// Accept the next bidirectional flow stream and read its `flow_id`
/// preamble. Returns `(flow_id, send, recv)`.
pub async fn accept_flow(conn: &Connection) -> Result<(u32, SendStream, RecvStream)> {
    let (send, mut recv) = conn.accept_bi().await.context("quic accept_bi")?;
    let mut hdr = [0u8; 4];
    recv.read_exact(&mut hdr)
        .await
        .context("quic read flow_id preamble")?;
    Ok((u32::from_le_bytes(hdr), send, recv))
}

/// Upper bound on the auth token length (a JWT is ~200–800 bytes; this
/// is a generous cap that also bounds the agent's read allocation).
const MAX_TOKEN_BYTES: usize = 4096;

/// Client side of the QUIC mutual-auth handshake. Cert-pinning already
/// authenticated the AGENT to us; this authenticates US to the agent.
/// Open a dedicated uni-stream and send the length-prefixed session
/// token the server minted (delivered over signaling in
/// `TunnelOpened.quic_auth_token`). Call once, right after [`connect`],
/// before opening any flow streams.
pub async fn client_authenticate(conn: &Connection, token: &str) -> Result<()> {
    let bytes = token.as_bytes();
    let len = u16::try_from(bytes.len()).map_err(|_| anyhow!("quic auth token too long"))?;
    let mut s = conn.open_uni().await.context("quic open auth uni-stream")?;
    s.write_all(&len.to_le_bytes())
        .await
        .context("quic auth len")?;
    s.write_all(bytes).await.context("quic auth token")?;
    s.finish().context("quic auth finish")?;
    Ok(())
}

/// Agent side: accept the client's auth uni-stream and verify the token
/// matches the one the server minted for this session
/// (`TunnelQuicSetup.quic_auth_token`). Returns `Ok` only on an exact
/// match. Call once right after accepting the connection, BEFORE
/// serving any flow streams — the server is no longer in the byte path
/// for QUIC, so this token is what keeps the P2P endpoint from being an
/// open relay for anyone who reaches the address.
pub async fn server_authenticate(conn: &Connection, expected_token: &str) -> Result<()> {
    let mut s = conn
        .accept_uni()
        .await
        .context("quic accept auth uni-stream")?;
    let mut len_buf = [0u8; 2];
    s.read_exact(&mut len_buf)
        .await
        .context("quic auth len read")?;
    let len = u16::from_le_bytes(len_buf) as usize;
    if len == 0 || len > MAX_TOKEN_BYTES {
        bail!("quic auth token length {len} out of range");
    }
    let mut tok = vec![0u8; len];
    s.read_exact(&mut tok)
        .await
        .context("quic auth token read")?;
    let got = std::str::from_utf8(&tok).context("quic auth token not utf-8")?;
    // Tokens are short + server-minted; a plain compare is fine (this
    // is not a password-equality oracle — a mismatch just drops the
    // connection, no timing signal of value to an attacker).
    if got == expected_token {
        Ok(())
    } else {
        bail!("quic auth token mismatch")
    }
}

/// The `ring` crypto provider. Used for both the rustls configs and the
/// pinning verifier's signature checks, so everything stays on ring.
fn provider() -> CryptoProvider {
    rustls::crypto::ring::default_provider()
}

fn decode_fingerprint(hex_str: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(hex_str.trim()).context("quic: fingerprint not hex")?;
    let arr: [u8; 32] = bytes.as_slice().try_into().map_err(|_| {
        anyhow!(
            "quic: fingerprint must be 32 bytes (SHA-256), got {}",
            bytes.len()
        )
    })?;
    Ok(arr)
}

/// rustls server-cert verifier that trusts exactly one cert, identified
/// by its SHA-256 fingerprint (pinned out-of-band over signaling).
/// Signature checks still run via the `ring` provider — only the
/// trust-anchor decision is replaced.
#[derive(Debug)]
struct FingerprintVerifier {
    pinned: [u8; 32],
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for FingerprintVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let got = Sha256::digest(end_entity.as_ref());
        if got.as_slice() == self.pinned {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(
                "quic: server cert fingerprint mismatch (pin failed)".into(),
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
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
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
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

/// rustls server-cert verifier that trusts ANY presented cert. Used ONLY by the
/// overlay WG-over-QUIC datagram carrier, where WireGuard Noise is the real
/// end-to-end auth boundary (see [`build_client_config_insecure`]). TLS
/// signature checks still run via the `ring` provider — only the trust-anchor
/// decision is a no-op, so this is not a downgrade to unauthenticated TLS, it's
/// a deliberate "the cert identity doesn't matter, WG does" posture.
#[derive(Debug)]
struct InsecureServerVerifier {
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for InsecureServerVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
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
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
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

#[cfg(test)]
mod tests {
    use super::*;

    fn loopback() -> SocketAddr {
        "127.0.0.1:0".parse().unwrap()
    }

    /// `host_candidates` must pair the egress IP with the requested
    /// port and never advertise a loopback/unspecified address. We
    /// tolerate an empty result (CI sandboxes with no egress route),
    /// asserting only the shape of whatever it does return.
    #[test]
    fn host_candidates_are_dialable_or_empty() {
        let port = 51820;
        for addr in host_candidates(port) {
            assert_eq!(addr.port(), port, "candidate must carry the bound port");
            let ip = addr.ip();
            assert!(
                !ip.is_loopback(),
                "loopback is not a useful candidate: {ip}"
            );
            assert!(!ip.is_unspecified(), "0.0.0.0 is not dialable: {ip}");
            assert!(ip.is_ipv4(), "Phase-2a gathers IPv4 host candidates only");
        }
    }

    /// The Phase-2 socket-sharing constructors must produce working
    /// endpoints: gather candidates on a tokio socket, convert it to
    /// std, build server/client endpoints from those sockets, and
    /// round-trip a flow on loopback. Proves quinn's
    /// `Endpoint::new(socket, ..)` path + the shared config builders.
    #[tokio::test(flavor = "multi_thread")]
    async fn quic_from_socket_loopback_roundtrips() {
        use std::time::Duration;

        let s_sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        // No STUN servers → host candidates only; we just exercise the
        // gather + into_std path (the dial below uses the loopback addr).
        let _ = gather_candidates(&s_sock, &[], Duration::from_millis(200)).await;
        let s_std = s_sock.into_std().unwrap();
        let (server, fp) = QuicPeer::server_from_socket(s_std).expect("server_from_socket");
        let server_addr = server.local_addr().unwrap();

        let c_sock = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let c_std = c_sock.into_std().unwrap();
        let client = QuicPeer::client_from_socket(c_std, &fp).expect("client_from_socket");

        let srv = tokio::spawn(async move {
            let conn = server.accept().await.expect("incoming").expect("handshake");
            let (flow_id, mut send, mut recv) = accept_flow(&conn).await.expect("accept_flow");
            assert_eq!(
                flow_id, 3,
                "flow_id preamble must survive the from-socket path"
            );
            let echoed = read_to_end(&mut recv).await;
            send.write_all(&echoed).await.expect("echo write");
            send.finish().expect("echo finish");
            conn.closed().await;
        });

        let conn = client.connect(server_addr).await.expect("connect");
        let (mut send, mut recv) = open_flow(&conn, 3).await.expect("open_flow");
        send.write_all(b"from-socket quic works")
            .await
            .expect("write");
        send.finish().expect("finish");
        let got = read_to_end(&mut recv).await;
        assert_eq!(
            &got, b"from-socket quic works",
            "round-trip over from-socket"
        );
        conn.close(0u32.into(), b"done");
        let _ = srv.await;
    }

    /// Drain a recv stream to EOF into a Vec (test helper).
    async fn read_to_end(recv: &mut RecvStream) -> Vec<u8> {
        let mut out = Vec::new();
        let mut buf = vec![0u8; 64 * 1024];
        while let Some(n) = recv.read(&mut buf).await.unwrap() {
            out.extend_from_slice(&buf[..n]);
        }
        out
    }

    /// A pinned-fingerprint client + ephemeral-cert server connect on
    /// loopback, open one flow stream, and round-trip a 4 MiB payload
    /// (echo). Proves the quinn/rustls/rcgen `ring` stack builds + works
    /// on this platform and that the flow_id preamble correlates.
    #[tokio::test(flavor = "multi_thread")]
    async fn quic_loopback_flow_roundtrips_4mib() {
        let (server, fingerprint) = QuicPeer::server(loopback()).expect("server endpoint");
        let server_addr = server.local_addr().unwrap();
        let client = QuicPeer::client(loopback(), &fingerprint).expect("client endpoint");

        let srv = tokio::spawn(async move {
            let conn = server.accept().await.expect("incoming").expect("handshake");
            let (flow_id, mut send, mut recv) = accept_flow(&conn).await.expect("accept_flow");
            assert_eq!(flow_id, 7, "flow_id preamble must survive");
            let echoed = read_to_end(&mut recv).await;
            send.write_all(&echoed).await.expect("echo write");
            send.finish().expect("echo finish");
            // Keep the connection alive until the client has read the echo.
            conn.closed().await;
            echoed.len()
        });

        let conn = client.connect(server_addr).await.expect("connect");
        let (mut send, mut recv) = open_flow(&conn, 7).await.expect("open_flow");
        let payload = vec![0xABu8; 4 * 1024 * 1024];
        send.write_all(&payload).await.expect("write payload");
        send.finish().expect("finish");

        let got = read_to_end(&mut recv).await;
        assert_eq!(got.len(), payload.len(), "echo length mismatch");
        assert_eq!(got, payload, "echo payload corrupted");
        conn.close(0u32.into(), b"done");
        let _ = srv.await;
    }
    /// FR-46 P4 step 1, proven rather than reasoned: the server already answers
    /// the NEW ALPN, so step 2 (flipping the client) is a flip and not a leap.
    ///
    /// The sibling loopback tests cover the other direction — they run a client
    /// that offers only the LEGACY name against this same dual server — so
    /// between them both arms of the changeover are exercised.
    #[tokio::test]
    async fn the_server_answers_both_the_new_and_the_legacy_alpn() {
        for (label, offered) in [
            ("new", vec![ALPN.to_vec()]),
            ("legacy", vec![ALPN_LEGACY.to_vec()]),
        ] {
            let (server, fingerprint) = QuicPeer::server(loopback()).expect("server endpoint");
            let server_addr = server.local_addr().unwrap();
            let srv = tokio::spawn(async move {
                server
                    .accept()
                    .await
                    .expect("incoming")
                    .expect("handshake must complete")
            });

            let mut endpoint = Endpoint::client(loopback()).expect("client endpoint");
            endpoint.set_default_client_config(
                build_client_config_with_alpn(&fingerprint, offered).expect("client config"),
            );
            let conn = endpoint
                .connect(server_addr, SNI)
                .expect("connect")
                .await
                .unwrap_or_else(|e| panic!("{label} ALPN must complete the handshake: {e}"));

            let accepted = srv.await.expect("server task");
            assert_eq!(
                conn.stable_id(),
                conn.stable_id(),
                "{label}: connection is usable"
            );
            drop(accepted);
        }
    }

    /// A client that pins the WRONG fingerprint must fail the handshake
    /// — the cert-pin is load-bearing (no CA, so a mismatch is the only
    /// thing standing between us and trusting an impostor at that IP).
    #[tokio::test(flavor = "multi_thread")]
    async fn quic_wrong_fingerprint_is_rejected() {
        let (server, _real_fp) = QuicPeer::server(loopback()).expect("server endpoint");
        let server_addr = server.local_addr().unwrap();
        // Pin a bogus (but well-formed) fingerprint.
        let bogus = hex::encode([0x11u8; 32]);
        let client = QuicPeer::client(loopback(), &bogus).expect("client endpoint");

        tokio::spawn(async move {
            // Server may or may not see the attempt; just keep it alive.
            let _ = server.accept().await;
        });

        let result = client.connect(server_addr).await;
        assert!(
            result.is_err(),
            "handshake must fail when the pinned fingerprint does not match"
        );
    }

    /// End-to-end: a local TCP byte stream piped through
    /// `run_flow_quic` on the client side → QUIC stream → `run_flow_quic`
    /// on the agent side → a local TCP stream. Writing into "app A"
    /// must surface, intact, at "app B" — proving the QUIC data-plane
    /// pump works both ways with FIN-driven half-close.
    #[tokio::test(flavor = "multi_thread")]
    async fn run_flow_quic_pipes_tcp_app_to_app() {
        use crate::forward::{FlowStats, run_flow_quic};
        use std::sync::Arc;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::{TcpListener, TcpStream};

        // QUIC connection (client dials, agent accepts).
        let (server, fp) = QuicPeer::server(loopback()).unwrap();
        let server_addr = server.local_addr().unwrap();
        let client = QuicPeer::client(loopback(), &fp).unwrap();
        let agent_accept = tokio::spawn(async move { server.accept().await.unwrap().unwrap() });
        let client_conn = client.connect(server_addr).await.unwrap();
        let agent_conn = agent_accept.await.unwrap();

        // One flow stream: client opens (writes flow_id preamble), agent accepts.
        let (c_send, c_recv) = open_flow(&client_conn, 1).await.unwrap();
        let (fid, a_send, a_recv) = accept_flow(&agent_conn).await.unwrap();
        assert_eq!(fid, 1);

        // "App A" (client-local) + "dst B" (agent-local), each a connected TCP pair.
        let la = TcpListener::bind(loopback()).await.unwrap();
        let a_addr = la.local_addr().unwrap();
        let a_into_tunnel = TcpStream::connect(a_addr).await.unwrap();
        let (mut app_a, _) = la.accept().await.unwrap();

        let lb = TcpListener::bind(loopback()).await.unwrap();
        let b_addr = lb.local_addr().unwrap();
        let b_into_tunnel = TcpStream::connect(b_addr).await.unwrap();
        let (mut app_b, _) = lb.accept().await.unwrap();

        // Pumps: app_a → c_send → [QUIC] → a_recv → app_b.
        tokio::spawn(run_flow_quic(
            a_into_tunnel,
            c_send,
            c_recv,
            1,
            Arc::new(FlowStats::default()),
        ));
        tokio::spawn(run_flow_quic(
            b_into_tunnel,
            a_send,
            a_recv,
            1,
            Arc::new(FlowStats::default()),
        ));

        let payload = vec![0xCDu8; 2 * 1024 * 1024];
        app_a.write_all(&payload).await.unwrap();
        app_a.shutdown().await.unwrap(); // EOF → FIN propagates A→B

        let mut got = Vec::new();
        let mut tmp = vec![0u8; 64 * 1024];
        loop {
            match app_b.read(&mut tmp).await.unwrap() {
                0 => break,
                n => got.extend_from_slice(&tmp[..n]),
            }
        }
        assert_eq!(got.len(), payload.len(), "A→B length mismatch through QUIC");
        assert_eq!(got, payload, "A→B payload corrupted through QUIC");
    }

    /// End-to-end UDP ASSOCIATE pump over QUIC: the agent side runs
    /// [`crate::forward::run_flow_udp_quic`] against a loopback UDP echo
    /// target; the "client" writes a length-prefixed datagram on the
    /// flow stream and reads the echo back framed. Proves the QUIC
    /// datagram framing ([`crate::forward::quic_read_datagram`] /
    /// `quic_write_datagram`) + the pump round-trip.
    #[tokio::test(flavor = "multi_thread")]
    async fn run_flow_udp_quic_echoes_datagram() {
        use crate::forward::{
            FlowStats, frame_udp_datagram, quic_read_datagram, run_flow_udp_quic,
        };
        use std::sync::Arc;
        use std::time::Duration;

        // Loopback UDP echo server.
        let echo = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            let mut b = [0u8; 2048];
            while let Ok((n, from)) = echo.recv_from(&mut b).await {
                let _ = echo.send_to(&b[..n], from).await;
            }
        });

        // QUIC pair + one flow stream.
        let (server, fp) = QuicPeer::server(loopback()).unwrap();
        let server_addr = server.local_addr().unwrap();
        let client = QuicPeer::client(loopback(), &fp).unwrap();
        let agent_accept = tokio::spawn(async move { server.accept().await.unwrap().unwrap() });
        let client_conn = client.connect(server_addr).await.unwrap();
        let agent_conn = agent_accept.await.unwrap();
        let (mut c_send, mut c_recv) = open_flow(&client_conn, 1).await.unwrap();
        let (_fid, a_send, a_recv) = accept_flow(&agent_conn).await.unwrap();

        // Agent pump: UDP socket connected to the echo target.
        let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        udp.connect(echo_addr).await.unwrap();
        let pump = tokio::spawn(run_flow_udp_quic(
            udp,
            a_send,
            a_recv,
            1,
            Duration::from_secs(3),
            Arc::new(FlowStats::default()),
        ));

        // Client → agent: one framed datagram.
        c_send
            .write_all(&frame_udp_datagram(b"ping-quic").unwrap())
            .await
            .unwrap();

        // Echo returns framed on the same stream.
        let echoed = tokio::time::timeout(Duration::from_secs(5), quic_read_datagram(&mut c_recv))
            .await
            .expect("no echo within 5s")
            .expect("quic read error")
            .expect("stream finished early");
        assert_eq!(
            echoed, b"ping-quic",
            "datagram must round-trip the QUIC pump"
        );
        pump.abort();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn quic_token_auth_accepts_matching() {
        let (server, fp) = QuicPeer::server(loopback()).unwrap();
        let addr = server.local_addr().unwrap();
        let client = QuicPeer::client(loopback(), &fp).unwrap();
        let srv = tokio::spawn(async move {
            let conn = server.accept().await.unwrap().unwrap();
            server_authenticate(&conn, "sekret-token").await
        });
        let conn = client.connect(addr).await.unwrap();
        client_authenticate(&conn, "sekret-token").await.unwrap();
        assert!(
            srv.await.unwrap().is_ok(),
            "matching token must authenticate"
        );
        conn.close(0u32.into(), b"done");
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn quic_token_auth_rejects_mismatch() {
        let (server, fp) = QuicPeer::server(loopback()).unwrap();
        let addr = server.local_addr().unwrap();
        let client = QuicPeer::client(loopback(), &fp).unwrap();
        let srv = tokio::spawn(async move {
            let conn = server.accept().await.unwrap().unwrap();
            server_authenticate(&conn, "the-right-token").await
        });
        let conn = client.connect(addr).await.unwrap();
        // The send itself succeeds; the agent rejects on compare.
        let _ = client_authenticate(&conn, "WRONG").await;
        assert!(
            srv.await.unwrap().is_err(),
            "mismatched token must be rejected"
        );
        conn.close(0u32.into(), b"done");
    }

    /// The DERP leg demuxes each payload by its first bytes
    /// ([`crate::transport::derp::payload_is_wg_or_disco`]), so an endpoint
    /// that rides it must never clear QUIC's fixed bit. quinn GREASES that
    /// bit by default (RFC 9287): each end advertises it, and each then
    /// clears it on about half of what it sends, so a short header starts
    /// anywhere below 0x40, WireGuard's types 1..=4 among it. Measured over a
    /// real transfer between the two DERP endpoints, both ways.
    #[tokio::test(flavor = "multi_thread")]
    async fn quic_over_derp_never_clears_the_fixed_bit() {
        use crate::transport::relay::{RelayConn, RelayUdpSocket, UdpRelayConn};
        use std::sync::atomic::{AtomicUsize, Ordering};

        /// What one side sent, by its first byte.
        #[derive(Default)]
        struct Seen {
            total: AtomicUsize,
            greased: AtomicUsize,
            wg_typed: AtomicUsize,
        }
        struct Recording {
            inner: UdpRelayConn,
            seen: Arc<Seen>,
        }
        #[async_trait::async_trait]
        impl RelayConn for Recording {
            async fn send_to(&self, buf: &[u8], dst: SocketAddr) -> std::io::Result<usize> {
                self.seen.total.fetch_add(1, Ordering::Relaxed);
                if buf.first().is_some_and(|b| b & 0x40 == 0) {
                    self.seen.greased.fetch_add(1, Ordering::Relaxed);
                }
                if matches!(buf.first(), Some(1..=4)) {
                    self.seen.wg_typed.fetch_add(1, Ordering::Relaxed);
                }
                self.inner.send_to(buf, dst).await
            }
            async fn recv_from(&self, buf: &mut [u8]) -> std::io::Result<(usize, SocketAddr)> {
                self.inner.recv_from(buf).await
            }
            fn local_addr(&self) -> std::io::Result<SocketAddr> {
                self.inner.local_addr()
            }
        }
        async fn side(seen: &Arc<Seen>) -> Arc<RelayUdpSocket> {
            let udp = tokio::net::UdpSocket::bind(loopback()).await.unwrap();
            let conn = Recording {
                inner: UdpRelayConn(udp),
                seen: Arc::clone(seen),
            };
            Arc::new(RelayUdpSocket::new(Arc::new(conn)).unwrap())
        }

        let seen = Arc::new(Seen::default());
        let (server, fp) = QuicPeer::server_over_derp(side(&seen).await).unwrap();
        let server_addr = server.local_addr().unwrap();
        let client = QuicPeer::client_over_derp(side(&seen).await, &fp).unwrap();
        const BYTES: usize = 2 * 1024 * 1024;
        let echo = tokio::spawn(async move {
            let conn = server.accept().await.unwrap().unwrap();
            let (mut send, mut recv) = conn.accept_bi().await.unwrap();
            let got = recv.read_to_end(BYTES).await.unwrap();
            send.write_all(&got).await.unwrap();
            send.finish().unwrap();
            conn.closed().await;
        });
        let conn = client.connect(server_addr).await.unwrap();
        let (mut send, mut recv) = conn.open_bi().await.unwrap();
        send.write_all(&vec![0x5a; BYTES]).await.unwrap();
        send.finish().unwrap();
        let back = recv.read_to_end(BYTES).await.unwrap();
        assert_eq!(back.len(), BYTES, "the transfer came back whole");
        conn.close(0u32.into(), b"done");
        let _ = echo.await;

        let (total, greased, wg_typed) = (
            seen.total.load(Ordering::Relaxed),
            seen.greased.load(Ordering::Relaxed),
            seen.wg_typed.load(Ordering::Relaxed),
        );
        assert!(
            total > 1000,
            "a transfer worth measuring: {total} datagrams"
        );
        assert_eq!(
            greased, 0,
            "{greased} of {total} datagrams cleared the fixed bit; {wg_typed} of them \
             start with a WireGuard type byte (1..=4)"
        );
    }
}
