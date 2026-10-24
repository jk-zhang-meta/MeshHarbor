// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! Overlay L3 data plane — userspace WireGuard mesh (Phase 2+).
//!
//! Feature-gated behind `overlay`. Pulls in `boringtun` for the Noise
//! crypto state machine; everything else (carrier selection, routing,
//! netmap application) is Roomler code.
//!
//! Layout:
//! * [`wg`] — the [`wg::WgDevice`]: a static keypair + a per-peer
//!   `boringtun::noise::Tunn`, each bridged to a [`wg::Carrier`] (a
//!   direct UDP socket or a coturn [`RelayConn`](crate::transport::relay::RelayConn)).
//! * [`router`] — the `overlay_ip → wg_public_key` crypto-routing table
//!   (boringtun's `Tunn` is single-peer, so the `allowed_ips` map lives
//!   here).
//! * [`netmap`] — decode a signed `rc:overlay.netmap` peer into a
//!   routable [`netmap::PeerConfig`].
//! * [`tun`] — the [`tun::TunIo`] OS-NIC seam (`SystemTun` behind
//!   `overlay-l3`; an in-memory mock in tests).
//! * [`bridge`] — the TUN↔`WgDevice` packet pump ([`bridge::run_bridge`]).
//! * [`runtime`] — the node runtime ([`runtime::OverlayRuntime`]): join →
//!   netmap → install WG peers + bring up the TUN + pump packets.
//!
//! Identity: each node owns a stable Curve25519 keypair. The private
//! key never leaves the node; the base64 public key is registered with
//! the coordination server and distributed in the netmap.

pub mod bridge;
/// Multi-org v2 — the process-wide shared direct-carrier plane: one stable
/// socket set for EVERY org engine, inbound demultiplexed by WireGuard
/// receiver index (initiations by per-engine static-key trial).
pub mod carrier_plane;
pub mod dialer;
pub mod direct;
pub mod disco;
pub mod dns;
/// FR-97 P0b-2b — host state the daemon changes that must not outlive it
/// (IPv4 forwarding a Windows router turned on), refcounted in process and
/// persisted for the boot purge.
pub mod host_ledger;
/// FR-97 P3i — what the host's own firewall (firewalld, ufw) lets a mesh peer
/// reach on the overlay adapter; reported, never changed.
pub mod hostfw;
pub mod hosts;
pub mod ingress;
/// A LAN interface's own prefix route made unusable underneath it (a next
/// hop that is not on its LAN, a VPN's stale gateway): detected and repaired
/// with the prefix's two on-link halves. Never routes around a capture.
pub mod lan_repair;
pub(crate) mod lifecycle;
pub mod nat;
pub mod netcheck;
pub mod netmap;
/// Userspace TCP/IP stack (smoltcp) presented as a [`tun::TunIo`] — the
/// OS-free twin of [`tun::SystemTun`]. Feature `overlay-netstack`.
#[cfg(feature = "overlay-netstack")]
pub mod netstack;
/// SOCKS5-CONNECT front for the [`netstack`] — the app-facing half of the
/// OS-free path. Feature `overlay-netstack`.
#[cfg(feature = "overlay-netstack")]
pub mod netstack_socks;
/// netstate — the process-wide network-state monitor (ONE OS change
/// subscription, typed snapshots/deltas, non-blocking fan-out). Public: the
/// agent's signaling loop subscribes for its probe-then-cycle arm.
pub mod netstate;
/// FR-19 P1 — org-relay wire framing (Geneve `Opt Len 0`, pinned protocol,
/// 24-bit VNI). Framing and shape rules only: nothing here forwards, binds or
/// holds session state.
pub mod orgrelay;
pub(crate) mod path;
/// FR-97 P1b — a Mac serves as an exit or subnet router through pf.
pub(crate) mod pf;
pub mod relay_link;
pub mod router;
pub mod runtime;
/// FR-110 — the buffers a carrier socket asks for. At the OS default the
/// kernel dropped bursts before the daemon read them, and TCP inside the tunnel
/// read every drop as congestion.
pub(crate) mod sockbuf;
/// Port-intercept shim: terminates one TCP port of this node's overlay address
/// in the in-process [`netstack`] instead of handing it to the OS, so an
/// in-daemon service can own e.g. `:22` on a host where `sshd` already holds
/// `0.0.0.0:22` — and without binding a socket a firewall or EDR agent could
/// block. Feature `overlay-netstack`.
#[cfg(feature = "overlay-netstack")]
pub mod split_tun;
pub mod tun;
/// Linux TUN segmentation and receive offload (the virtio-net header):
/// splits the kernel's TSO super-packets on read, coalesces TCP runs on write.
/// Pure packet logic plus the `SystemTun` device glue.
#[cfg(any(all(target_os = "linux", feature = "overlay-l3"), test))]
pub(crate) mod tun_offload;
/// #2213 / #2220 — reading a UDP socket past the errors Windows reports about
/// an EARLIER datagram (an ICMP port-unreachable, as 10054), for every loop
/// that serves a real OS socket.
pub(crate) mod udp_batch;
pub(crate) mod udp_recv;
/// C4 — the warm TURN allocation's loop-side state and pure helpers
/// (`docs/overlay-warm-relay.md`).
pub(crate) mod warm_relay;
pub mod wg;

/// WFP firewall override (Windows + `overlay-l3`): hard-permit the
/// `roomler` adapter so the overlay survives a GPO-locked Defender Firewall.
#[cfg(all(feature = "overlay-l3", windows))]
pub mod wfp;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use boringtun::x25519::{PublicKey, StaticSecret};

/// A node's WireGuard static identity. The secret stays in the node's
/// secure storage; only [`WgKeypair::public_base64`] is published.
#[derive(Clone)]
pub struct WgKeypair {
    pub secret: StaticSecret,
    pub public: PublicKey,
}

impl WgKeypair {
    /// Generate a fresh Curve25519 keypair from the OS CSPRNG.
    pub fn generate() -> Self {
        use rand::RngCore;
        let mut bytes = [0u8; 32];
        rand::rng().fill_bytes(&mut bytes);
        let secret = StaticSecret::from(bytes);
        let public = PublicKey::from(&secret);
        Self { secret, public }
    }

    /// Reconstruct from a base64-encoded 32-byte secret (e.g. read back
    /// from config on restart).
    pub fn from_secret_base64(s: &str) -> Option<Self> {
        let raw = B64.decode(s.trim()).ok()?;
        let bytes: [u8; 32] = raw.try_into().ok()?;
        let secret = StaticSecret::from(bytes);
        let public = PublicKey::from(&secret);
        Some(Self { secret, public })
    }

    /// base64 of the 32-byte secret — for persisting to secure storage.
    pub fn secret_base64(&self) -> String {
        B64.encode(self.secret.to_bytes())
    }

    /// base64 of the 32-byte public key — what the netmap distributes.
    pub fn public_base64(&self) -> String {
        encode_public(&self.public)
    }
}

/// base64-encode a WireGuard public key (the netmap wire form).
pub fn encode_public(public: &PublicKey) -> String {
    B64.encode(public.to_bytes())
}

/// Decode a base64 WireGuard public key into raw bytes. `None` on bad
/// base64 or wrong length.
pub fn decode_public(s: &str) -> Option<[u8; 32]> {
    let raw = B64.decode(s.trim()).ok()?;
    raw.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keypair_roundtrips_through_base64() {
        let kp = WgKeypair::generate();
        let restored = WgKeypair::from_secret_base64(&kp.secret_base64()).unwrap();
        assert_eq!(kp.public.to_bytes(), restored.public.to_bytes());
        assert_eq!(kp.public_base64(), restored.public_base64());
    }

    #[test]
    fn public_key_codec_roundtrips() {
        let kp = WgKeypair::generate();
        let b64 = kp.public_base64();
        assert_eq!(decode_public(&b64), Some(kp.public.to_bytes()));
        assert!(decode_public("not-base64!!").is_none());
        assert!(decode_public("c2hvcnQ=").is_none()); // valid b64, wrong len
    }
}
