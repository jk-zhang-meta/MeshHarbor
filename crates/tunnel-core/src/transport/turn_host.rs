// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! `LocalTurnHost` — the corp host's enrolled agent hosts a small UDP TURN
//! server on loopback + its overlay IP, so the local browser (loopback, never
//! firewall-blocked) and the remote agent (over the WFP-permitted overlay) can
//! relay through it instead of the far coturn — the **loopback-TURN corp-relay
//! fix, Phase 1**. Design: `~/.claude/plans/meshharbor-loopback-turn-corp-relay.md`.
//!
//! Phase 0 (spike) proved two webrtc-rs peers converge relay-to-relay through
//! an in-process `turn::server::Server` with webrtc-rs installing the TURN
//! permissions itself (`transport::relay::turn_tests::
//! webrtc_peers_relay_through_self_hosted_turn`). Phase 1 promotes that
//! test-only blueprint (`loopback_turn_server()`) to a reusable prod module:
//! configurable bind + relay address + stateless coturn-REST auth.
//!
//! Auth model: the agent hosts the TURN with a **per-instance secret** (it
//! never holds the cluster coturn secret). It mints short-lived creds for the
//! browser + the remote agent via [`LocalTurnHost::mint_credentials`] and
//! validates them statelessly here (recompute the password from the username).
//! Keying matches the server's `remote_control::turn_creds`
//! (HMAC-SHA1(secret, "{expiry}:{user_id}")) so the cred SHAPE is identical.
//!
//! NOT in Phase 1 (tracked separately): wiring the minted creds into the
//! browser's `iceServers` + the Hub's remote-agent push (Phase 2); excluding
//! loopback/overlay relay addrs from the agent's cap classifier (Phase 3);
//! lifecycle + gating on the agent (Phase 4). This module is inert until a
//! caller starts it.

use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use hmac::{Hmac, Mac};
use sha1::Sha1;
use turn::auth::{AuthHandler, generate_auth_key};
use turn::relay::relay_static::RelayAddressGeneratorStatic;
use turn::server::Server;
use turn::server::config::{ConnConfig, ServerConfig};
use webrtc_util::vnet::net::Net;

type HmacSha1 = Hmac<Sha1>;

/// coturn REST-convention password for `username` under `secret`:
/// `hex(HMAC-SHA1(secret, username))`. (coturn base64-encodes; we hex-encode —
/// the password string is opaque to the client, and the local host both mints
/// AND validates, so the encoding only needs to be self-consistent. The
/// HMAC-SHA1 keying matches `remote_control::turn_creds` so the wire shape is
/// unchanged.)
fn mint_password(secret: &[u8], username: &str) -> String {
    let mut mac = HmacSha1::new_from_slice(secret).expect("HMAC accepts any key length");
    mac.update(username.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Stateless long-term-credential auth: recompute the expected password from
/// the username via the shared secret, then the RFC 5389 key. No per-client
/// state — any cred minted by [`LocalTurnHost::mint_credentials`] validates and
/// nothing else does. (Note: a REST cred is bearer — an `{expiry}:{uid}`
/// username with the matching HMAC password is accepted regardless of expiry
/// here; coturn enforces expiry via the timestamp. Phase 2 can add an expiry
/// check when creds are minted server-agnostically.)
struct RestAuth {
    secret: Vec<u8>,
}

impl AuthHandler for RestAuth {
    fn auth_handle(
        &self,
        username: &str,
        realm: &str,
        _src: SocketAddr,
    ) -> std::result::Result<Vec<u8>, turn::Error> {
        let password = mint_password(&self.secret, username);
        Ok(generate_auth_key(username, realm, &password))
    }
}

/// A locally-hosted UDP TURN server. Keep the value alive for the server to
/// run; [`LocalTurnHost::stop`] (or drop) tears it down.
pub struct LocalTurnHost {
    server: Server,
    local_addr: SocketAddr,
    relay_ip: IpAddr,
    secret: Vec<u8>,
}

impl LocalTurnHost {
    /// Realm advertised to clients. Fixed so mint + validate line up; the
    /// realm-independent secret-derived password does the real work.
    pub const REALM: &'static str = "meshharbor.local";

    /// Start a TURN server on `bind` (use `0.0.0.0:0` so it receives on BOTH
    /// loopback AND the overlay adapter). `relay_ip` is handed out as the
    /// relay-candidate address — set it to the agent's overlay IP so the remote
    /// agent can route to allocated relays over the overlay. `secret` is this
    /// host's per-instance TURN secret (generate ~32 random bytes per run).
    pub async fn start(bind: SocketAddr, relay_ip: IpAddr, secret: Vec<u8>) -> Result<Self> {
        Self::start_with(
            bind,
            relay_ip,
            secret,
            Box::new(RelayAddressGeneratorStatic {
                relay_address: relay_ip,
                address: relay_ip.to_string(),
                net: Arc::new(Net::new(None)),
            }),
        )
        .await
    }

    /// FR-121 — the same host on a node whose overlay is the userspace
    /// netstack (no TUN, so no OS socket can bind the overlay IP): each
    /// allocation's relay socket is a netstack UDP socket on `relay_ip`, so
    /// relayed traffic is mesh traffic and goes wherever the mesh routes it.
    #[cfg(feature = "overlay-netstack")]
    pub async fn start_netstack(
        bind: SocketAddr,
        relay_ip: IpAddr,
        secret: Vec<u8>,
        netstack: crate::overlay::netstack::NetstackHandle,
    ) -> Result<Self> {
        Self::start_with(
            bind,
            relay_ip,
            secret,
            Box::new(netstack_relay::NetstackRelayGenerator { netstack, relay_ip }),
        )
        .await
    }

    async fn start_with(
        bind: SocketAddr,
        relay_ip: IpAddr,
        secret: Vec<u8>,
        relay_addr_generator: Box<dyn turn::relay::RelayAddressGenerator + Send + Sync>,
    ) -> Result<Self> {
        let conn = Arc::new(
            tokio::net::UdpSocket::bind(bind)
                .await
                .with_context(|| format!("bind local TURN socket on {bind}"))?,
        );
        let local_addr = conn.local_addr().context("local TURN socket local_addr")?;
        let server = Server::new(ServerConfig {
            conn_configs: vec![ConnConfig {
                conn,
                relay_addr_generator,
            }],
            realm: Self::REALM.to_owned(),
            auth_handler: Arc::new(RestAuth {
                secret: secret.clone(),
            }),
            // 0 == the turn crate's built-in default channel-bind lifetime.
            channel_bind_timeout: Duration::from_secs(0),
            alloc_close_notify: None,
        })
        .await
        .context("start local TURN server")?;
        Ok(Self {
            server,
            local_addr,
            relay_ip,
            secret,
        })
    }

    /// The socket the server bound. The browser dials `turn:127.0.0.1:{port}`
    /// (loopback); the remote agent dials `turn:{overlay_ip}:{port}`. Both
    /// share this port.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// The relay-candidate address handed out (the overlay IP in prod).
    pub fn relay_ip(&self) -> IpAddr {
        self.relay_ip
    }

    /// Mint a short-lived coturn-REST credential for `user_id`. Give these to
    /// the browser (its `iceServers` entry) and the remote agent (Hub push).
    /// `now_unix` is injected for testability; see [`Self::mint_credentials_now`].
    pub fn mint_credentials(
        &self,
        user_id: &str,
        ttl: Duration,
        now_unix: u64,
    ) -> (String, String) {
        let expiry = now_unix.saturating_add(ttl.as_secs());
        let username = format!("{expiry}:{user_id}");
        let password = mint_password(&self.secret, &username);
        (username, password)
    }

    /// [`Self::mint_credentials`] using the system clock.
    /// FR-121 — [`Self::mint_credentials_now`] for a holder of the host's
    /// secret but not the host (the session code mints for its own peer).
    pub fn mint_with_secret(secret: &[u8], user_id: &str, ttl: Duration) -> (String, String) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let username = format!("{}:{user_id}", now.saturating_add(ttl.as_secs()));
        let password = mint_password(secret, &username);
        (username, password)
    }

    pub fn mint_credentials_now(&self, user_id: &str, ttl: Duration) -> (String, String) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.mint_credentials(user_id, ttl, now)
    }

    /// Stop the server and free the socket.
    pub async fn stop(self) -> Result<()> {
        self.server.close().await.context("close local TURN server")
    }
}

/// FR-121 — TURN relay sockets inside the userspace netstack.
#[cfg(feature = "overlay-netstack")]
mod netstack_relay {
    use std::net::{IpAddr, SocketAddr};
    use std::sync::Arc;

    use async_trait::async_trait;
    use webrtc_util::Conn;

    use crate::overlay::netstack::{NetstackHandle, NsUdpSender, NsUdpSocket};

    /// Allocates each TURN relay address as a netstack UDP socket on the
    /// node's overlay address. A requested port is not honoured (the netstack
    /// picks an ephemeral one), which RFC 8656 allows for a plain allocation.
    pub(super) struct NetstackRelayGenerator {
        pub(super) netstack: NetstackHandle,
        pub(super) relay_ip: IpAddr,
    }

    #[async_trait]
    impl turn::relay::RelayAddressGenerator for NetstackRelayGenerator {
        fn validate(&self) -> Result<(), turn::Error> {
            Ok(())
        }

        async fn allocate_conn(
            &self,
            use_ipv4: bool,
            _requested_port: u16,
        ) -> Result<(Arc<dyn Conn + Send + Sync>, SocketAddr), turn::Error> {
            if use_ipv4 != self.relay_ip.is_ipv4() {
                return Err(turn::Error::ErrNoAvailableConns);
            }
            let socket = self
                .netstack
                .udp_bind()
                .await
                .map_err(|e| turn::Error::Other(format!("netstack udp_bind: {e}")))?;
            let local = SocketAddr::new(self.relay_ip, socket.local_port());
            let (closed, _) = tokio::sync::watch::channel(false);
            let conn = NsRelayConn {
                tx: socket.sender(),
                rx: tokio::sync::Mutex::new(Some(socket)),
                local,
                closed,
            };
            Ok((Arc::new(conn), local))
        }
    }

    /// One allocation's relay socket. Receiving needs the socket mutably, so
    /// it sits behind a lock; `close` wakes a pending receive and drops the
    /// socket, which frees its netstack port.
    struct NsRelayConn {
        tx: NsUdpSender,
        rx: tokio::sync::Mutex<Option<NsUdpSocket>>,
        local: SocketAddr,
        closed: tokio::sync::watch::Sender<bool>,
    }

    fn io_err(e: std::io::Error) -> webrtc_util::Error {
        webrtc_util::Error::from(e)
    }

    #[async_trait]
    impl Conn for NsRelayConn {
        async fn connect(&self, _addr: SocketAddr) -> webrtc_util::Result<()> {
            Err(webrtc_util::Error::Other("connect is not supported".into()))
        }

        async fn recv(&self, buf: &mut [u8]) -> webrtc_util::Result<usize> {
            self.recv_from(buf).await.map(|(n, _)| n)
        }

        async fn recv_from(&self, buf: &mut [u8]) -> webrtc_util::Result<(usize, SocketAddr)> {
            let mut closed = self.closed.subscribe();
            let mut guard = self.rx.lock().await;
            let Some(socket) = guard.as_mut() else {
                return Err(webrtc_util::Error::ErrUseClosedNetworkConn);
            };
            tokio::select! {
                r = socket.recv_from() => {
                    let (data, from) = r.map_err(io_err)?;
                    let n = data.len().min(buf.len());
                    buf[..n].copy_from_slice(&data[..n]);
                    Ok((n, from))
                }
                _ = closed.wait_for(|c| *c) => Err(webrtc_util::Error::ErrUseClosedNetworkConn),
            }
        }

        async fn send(&self, _buf: &[u8]) -> webrtc_util::Result<usize> {
            Err(webrtc_util::Error::Other("send needs a destination".into()))
        }

        async fn send_to(&self, buf: &[u8], target: SocketAddr) -> webrtc_util::Result<usize> {
            if *self.closed.borrow() {
                return Err(webrtc_util::Error::ErrUseClosedNetworkConn);
            }
            self.tx.send_to(buf, target).await.map_err(io_err)?;
            Ok(buf.len())
        }

        fn local_addr(&self) -> webrtc_util::Result<SocketAddr> {
            Ok(self.local)
        }

        fn remote_addr(&self) -> Option<SocketAddr> {
            None
        }

        async fn close(&self) -> webrtc_util::Result<()> {
            self.closed.send_replace(true);
            self.rx.lock().await.take();
            Ok(())
        }

        fn as_any(&self) -> &(dyn std::any::Any + Send + Sync) {
            self
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transport::relay::RelayConn;
    use std::net::Ipv4Addr;

    /// Phase 1: the prod `LocalTurnHost` accepts a cred it minted and rejects a
    /// bogus one (stateless REST auth over a per-instance secret), and hands out
    /// relay candidates on the configured relay IP. Proves the module + auth
    /// end-to-end via a real `turn` client allocation (lighter than two full
    /// webrtc peers, which the Phase-0 spike already covered).
    /// FR-121 — on a netstack node the TURN relay lives inside the mesh: a
    /// client on loopback allocates, its relay address is the node's overlay
    /// address, and datagrams it relays reach — and come back from — another
    /// node's netstack over WireGuard, with no TUN and no OS overlay socket.
    #[cfg(feature = "overlay-netstack")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_netstack_turn_relays_into_the_mesh() {
        use crate::overlay::WgKeypair;
        use crate::overlay::bridge::run_bridge;
        use crate::overlay::netstack::Netstack;
        use crate::overlay::tun::TunIo;
        use crate::overlay::wg::{Carrier, WgDevice};
        use tokio::net::UdpSocket;

        let a_ip = Ipv4Addr::new(100, 64, 0, 1);
        let b_ip = Ipv4Addr::new(100, 64, 0, 2);
        let ka = WgKeypair::generate();
        let kb = WgKeypair::generate();
        let sock_a = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let sock_b = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let (addr_a, addr_b) = (sock_a.local_addr().unwrap(), sock_b.local_addr().unwrap());
        let (mut dev_a, rx_a) = WgDevice::new(ka.secret.clone());
        let (mut dev_b, rx_b) = WgDevice::new(kb.secret.clone());
        dev_a.add_peer(
            kb.public.to_bytes(),
            b_ip,
            Carrier::direct(sock_a.clone(), addr_b),
            true,
        );
        dev_b.add_peer(
            ka.public.to_bytes(),
            a_ip,
            Carrier::direct(sock_b.clone(), addr_a),
            false,
        );
        let a = Netstack::start(a_ip, 10, 1280);
        let b = Netstack::start(b_ip, 10, 1280);
        tokio::spawn(run_bridge(
            a.tun.clone() as Arc<dyn TunIo>,
            Arc::new(dev_a),
            rx_a,
        ));
        tokio::spawn(run_bridge(
            b.tun.clone() as Arc<dyn TunIo>,
            Arc::new(dev_b),
            rx_b,
        ));

        let host = LocalTurnHost::start_netstack(
            (Ipv4Addr::LOCALHOST, 0).into(),
            IpAddr::V4(a_ip),
            b"fr121-netstack-relay-test-secret".to_vec(),
            a.handle.clone(),
        )
        .await
        .expect("start netstack TURN host");
        let (user, pass) = host.mint_credentials_now("viewer", Duration::from_secs(600));
        let relay = crate::transport::relay::allocate_turn_relay(
            host.local_addr(),
            user,
            pass,
            LocalTurnHost::REALM.to_owned(),
        )
        .await
        .expect("allocate on the netstack TURN host");
        let relay_addr = relay.local_addr().unwrap();
        assert_eq!(
            relay_addr.ip(),
            IpAddr::V4(a_ip),
            "the relay address is the overlay address"
        );

        let mut peer = b.handle.udp_bind().await.unwrap();
        let peer_addr = SocketAddr::new(IpAddr::V4(b_ip), peer.local_port());
        // The first datagram also installs the TURN permission for the peer.
        let got = tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                relay.send_to(b"over-the-mesh", peer_addr).await.unwrap();
                if let Ok(Ok(r)) =
                    tokio::time::timeout(Duration::from_millis(500), peer.recv_from()).await
                {
                    break r;
                }
            }
        })
        .await
        .expect("the relayed datagram reaches the other netstack");
        assert_eq!(got.0, b"over-the-mesh");
        assert_eq!(got.1, relay_addr, "it arrives from the relay address");

        peer.send_to(b"and-back", relay_addr).await.unwrap();
        let mut buf = [0u8; 64];
        let (n, from) = tokio::time::timeout(Duration::from_secs(10), relay.recv_from(&mut buf))
            .await
            .expect("the reply comes back through the relay")
            .unwrap();
        assert_eq!(&buf[..n], b"and-back");
        assert_eq!(from, peer_addr);
        host.stop().await.unwrap();
    }

    #[tokio::test(flavor = "multi_thread")]
    async fn accepts_minted_creds_rejects_bogus() {
        let secret = b"phase1-per-instance-secret-not-real".to_vec();
        let host = LocalTurnHost::start(
            (Ipv4Addr::LOCALHOST, 0).into(),
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            secret,
        )
        .await
        .expect("start local TURN host");

        // A minted cred allocates + lands a relay on the configured relay IP.
        let (user, pass) =
            host.mint_credentials("controller-uid", Duration::from_secs(600), 1_700_000_000);
        let relay = crate::transport::relay::allocate_turn_relay(
            host.local_addr(),
            user,
            pass,
            LocalTurnHost::REALM.to_owned(),
        )
        .await
        .expect("minted cred should allocate");
        assert!(
            relay.local_addr().unwrap().ip().is_loopback(),
            "relay addr on the configured relay IP"
        );
        drop(relay);

        // Same username, WRONG password → the stateless auth recomputes the
        // right key from the username and the MESSAGE-INTEGRITY check fails.
        let bad = tokio::time::timeout(
            Duration::from_secs(8),
            crate::transport::relay::allocate_turn_relay(
                host.local_addr(),
                "1700000600:controller-uid".to_owned(),
                "deadbeefdeadbeefdeadbeefdeadbeef".to_owned(),
                LocalTurnHost::REALM.to_owned(),
            ),
        )
        .await;
        assert!(
            matches!(bad, Err(_) | Ok(Err(_))),
            "bogus cred must not allocate (got {bad:?})"
        );

        host.stop().await.expect("stop local TURN host");
    }

    #[test]
    fn minted_password_is_deterministic_per_secret() {
        let s1 = b"secret-one".to_vec();
        let s2 = b"secret-two".to_vec();
        let u = "1700000600:uid";
        assert_eq!(
            mint_password(&s1, u),
            mint_password(&s1, u),
            "deterministic"
        );
        assert_ne!(
            mint_password(&s1, u),
            mint_password(&s2, u),
            "different secret ⇒ different password"
        );
        assert_ne!(
            mint_password(&s1, "1700000600:uid"),
            mint_password(&s1, "1700000601:uid"),
            "different username ⇒ different password"
        );
    }
}
