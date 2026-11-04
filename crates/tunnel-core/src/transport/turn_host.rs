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
        let conn = Arc::new(
            tokio::net::UdpSocket::bind(bind)
                .await
                .with_context(|| format!("bind local TURN socket on {bind}"))?,
        );
        let local_addr = conn.local_addr().context("local TURN socket local_addr")?;
        let server = Server::new(ServerConfig {
            conn_configs: vec![ConnConfig {
                conn,
                relay_addr_generator: Box::new(RelayAddressGeneratorStatic {
                    relay_address: relay_ip,
                    address: relay_ip.to_string(),
                    net: Arc::new(Net::new(None)),
                }),
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
