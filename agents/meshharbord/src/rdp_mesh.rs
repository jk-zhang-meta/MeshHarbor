// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! RDP over the mesh — the device owner's opt-in (`rdp_over_mesh`, default
//! OFF) that lets a netstack node answer RDP through the overlay.
//!
//! A node running the userspace stack (no OS TUN: a per-user Windows install,
//! a user-level macOS daemon) answers overlay TCP only on ports it listens on,
//! so `mh rdp` to it was refused (SOCKS REP 0x04). With the opt-in this module
//! listens on the RDP port the device itself reports ([`crate::rdp_caps`]) and
//! forwards each accepted connection to `127.0.0.1:<that port>` — never any
//! other address or port. Packets reach the netstack only after the overlay
//! ingress check (`Ingress::permits`: ACL and business-zone shaping), so this
//! opens no path that check does not already gate.
//!
//! - The key is device-owned and structurally absent from `DesiredConfig`.
//! - It is LIVE: every connection re-reads the config FILE, and an unreadable
//!   file reads as OFF. Turning it off also closes the listener within a beat
//!   ([`RECHECK`]), so the port is refused again, as before.
//! - Every connection is logged (peer, port, decision) under [`AUDIT`]. No
//!   content is ever logged or inspected.
//!
//! An OS-TUN node needs none of this: its OS stack answers the overlay.
//! [`mesh_reachable`] reports which case holds, as `rdp_mesh_reachable` in the
//! caps a controller sees.

use std::path::Path;
#[cfg(feature = "overlay-netstack")]
use std::path::PathBuf;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicBool, Ordering};

/// Log target for the per-connection audit line.
pub const AUDIT: &str = "meshharbor_rdp_mesh";

/// How often the supervisor re-checks the opt-in and the RDP probe.
#[cfg_attr(not(feature = "overlay-netstack"), allow(dead_code))]
const RECHECK: std::time::Duration = std::time::Duration::from_secs(15);

struct State {
    tenant_id: String,
    /// The opt-in as last read from the file.
    opted_in: AtomicBool,
    /// A netstack listener is armed on the reported RDP port right now.
    listening: AtomicBool,
}

static STATE: OnceLock<State> = OnceLock::new();

/// The per-connection gate. Every condition must hold, or the connection is
/// refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Forward,
    RefuseOptedOut,
    RefuseRdpUnavailable,
    RefusePortMismatch,
}

pub fn decide(
    opted_in: bool,
    rdp_available: bool,
    rdp_port: Option<u16>,
    listen_port: u16,
) -> Decision {
    if !opted_in {
        Decision::RefuseOptedOut
    } else if !rdp_available {
        Decision::RefuseRdpUnavailable
    } else if rdp_port != Some(listen_port) {
        Decision::RefusePortMismatch
    } else {
        Decision::Forward
    }
}

/// `rdp_mesh_reachable`: an RDP server, and an overlay that delivers to it —
/// the OS stack in TUN mode, or the opted-in listener in netstack mode.
pub fn reachable_from(
    rdp_available: bool,
    tun_up: bool,
    netstack_mode: bool,
    opted_in: bool,
    listening: bool,
) -> bool {
    rdp_available
        && if netstack_mode {
            opted_in && listening
        } else {
            tun_up
        }
}

/// What this device reports as `rdp_mesh_reachable` right now.
pub fn mesh_reachable(rdp_available: bool) -> bool {
    let Some(st) = STATE.get() else {
        return false;
    };
    let netstack_mode = crate::overlay_supervision::is_org_in_netstack_mode(&st.tenant_id);
    let tun_up = crate::overlay_supervision::effective_overlay_mode(&st.tenant_id, "") == "tun";
    reachable_from(
        rdp_available,
        tun_up,
        netstack_mode,
        st.opted_in.load(Ordering::Relaxed),
        st.listening.load(Ordering::Relaxed),
    )
}

/// The opt-in as the FILE says now; anything unreadable is OFF.
#[cfg_attr(not(feature = "overlay-netstack"), allow(dead_code))]
async fn opted_in_now(path: &Path) -> bool {
    let path = path.to_path_buf();
    tokio::task::spawn_blocking(move || {
        crate::config::load(&path)
            .map(|c| c.rdp_over_mesh)
            .unwrap_or(false)
    })
    .await
    .unwrap_or(false)
}

/// Start reporting, and on a netstack node supervise the opted-in forward for
/// the primary org. Idempotent; a no-op on the second call.
pub fn start(cfg: &crate::config::AgentConfig, config_path: &Path) {
    if STATE
        .set(State {
            tenant_id: cfg.tenant_id.clone(),
            opted_in: AtomicBool::new(cfg.rdp_over_mesh),
            listening: AtomicBool::new(false),
        })
        .is_err()
    {
        return;
    }
    #[cfg(feature = "overlay-netstack")]
    if let Ok(rt) = tokio::runtime::Handle::try_current() {
        let rx = crate::overlay::netstack_handle_rx(&cfg.tenant_id);
        rt.spawn(supervise(rx, config_path.to_path_buf()));
    }
    #[cfg(not(feature = "overlay-netstack"))]
    let _ = config_path;
}

#[cfg(feature = "overlay-netstack")]
async fn supervise(
    mut handle_rx: tokio::sync::watch::Receiver<
        Option<tunnel_core::overlay::netstack::NetstackHandle>,
    >,
    config_path: PathBuf,
) {
    let Some(st) = STATE.get() else { return };
    loop {
        let opted_in = opted_in_now(&config_path).await;
        st.opted_in.store(opted_in, Ordering::Relaxed);
        let rdp = crate::rdp_caps::current();
        let handle = handle_rx.borrow_and_update().clone();
        if let (Some(port), Some(handle)) = (rdp.port, handle)
            && decide(opted_in, rdp.available, rdp.port, port) == Decision::Forward
        {
            match handle.listen(port).await {
                Ok(listener) => {
                    st.listening.store(true, Ordering::Relaxed);
                    tracing::info!(target: AUDIT, port, "rdp over mesh: listening (forward to 127.0.0.1 only)");
                    serve(listener, port, &mut handle_rx, &config_path).await;
                    // Dropping the listener stops listening: the port is refused again.
                    st.listening.store(false, Ordering::Relaxed);
                    tracing::info!(target: AUDIT, port, "rdp over mesh: stopped listening");
                }
                Err(e) => {
                    tracing::warn!(target: AUDIT, port, error = %e, "rdp over mesh: could not listen")
                }
            }
        }
        tokio::select! {
            changed = handle_rx.changed() => if changed.is_err() { return },
            _ = tokio::time::sleep(RECHECK) => {}
        }
    }
}

/// Accept until the stack changes or a re-check says the gate no longer holds.
#[cfg(feature = "overlay-netstack")]
async fn serve(
    mut listener: tunnel_core::overlay::netstack::NsListener,
    port: u16,
    handle_rx: &mut tokio::sync::watch::Receiver<
        Option<tunnel_core::overlay::netstack::NetstackHandle>,
    >,
    config_path: &Path,
) {
    let mut tick = tokio::time::interval(RECHECK);
    tick.tick().await;
    loop {
        tokio::select! {
            accepted = listener.accept() => {
                let Some(stream) = accepted else { return };
                let path = config_path.to_path_buf();
                tokio::spawn(async move {
                    let rdp = crate::rdp_caps::current();
                    let opted_in = opted_in_now(&path).await;
                    if let Some(st) = STATE.get() {
                        st.opted_in.store(opted_in, Ordering::Relaxed);
                    }
                    let d = decide(opted_in, rdp.available, rdp.port, port);
                    forward_one(stream, port, d).await;
                });
            }
            _ = handle_rx.changed() => return,
            _ = tick.tick() => {
                let rdp = crate::rdp_caps::current();
                let opted_in = opted_in_now(config_path).await;
                if let Some(st) = STATE.get() {
                    st.opted_in.store(opted_in, Ordering::Relaxed);
                }
                if decide(opted_in, rdp.available, rdp.port, port) != Decision::Forward {
                    return;
                }
            }
        }
    }
}

/// Forward one accepted overlay connection to `127.0.0.1:<port>` when the gate
/// said so; otherwise drop it. Either way one audit line, never any content.
#[cfg(feature = "overlay-netstack")]
async fn forward_one(
    mut inbound: tunnel_core::overlay::netstack::NsTcpStream,
    port: u16,
    decision: Decision,
) {
    let peer = inbound.peer_addr();
    if decision != Decision::Forward {
        tracing::info!(target: AUDIT, %peer, port, decision = ?decision, "rdp over mesh: refused");
        return;
    }
    match tokio::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port)).await {
        Ok(mut local) => {
            tracing::info!(target: AUDIT, %peer, port, decision = ?decision, "rdp over mesh: forwarded to 127.0.0.1");
            let _ = local.set_nodelay(true);
            let _ = tokio::io::copy_bidirectional(&mut inbound, &mut local).await;
        }
        Err(e) => {
            tracing::info!(target: AUDIT, %peer, port, decision = "local_connect_failed", error = %e, "rdp over mesh: refused");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_gate_refuses_unless_every_condition_holds() {
        assert_eq!(decide(true, true, Some(3389), 3389), Decision::Forward);
        assert_eq!(
            decide(false, true, Some(3389), 3389),
            Decision::RefuseOptedOut
        );
        assert_eq!(
            decide(true, false, Some(3389), 3389),
            Decision::RefuseRdpUnavailable
        );
        assert_eq!(
            decide(true, true, Some(13389), 3389),
            Decision::RefusePortMismatch
        );
        assert_eq!(decide(true, true, None, 3389), Decision::RefusePortMismatch);
        // Opt-out wins over everything else.
        assert_eq!(decide(false, false, None, 3389), Decision::RefuseOptedOut);
    }

    #[test]
    fn reachability_needs_rdp_and_a_path_that_delivers() {
        // TUN mode: the OS stack answers; no opt-in needed.
        assert!(reachable_from(true, true, false, false, false));
        assert!(
            !reachable_from(true, false, false, true, true),
            "TUN not up yet"
        );
        // Netstack mode: only the opted-in, armed listener delivers.
        assert!(reachable_from(true, false, true, true, true));
        assert!(
            !reachable_from(true, false, true, false, true),
            "not opted in"
        );
        assert!(
            !reachable_from(true, false, true, true, false),
            "listener not armed"
        );
        // No RDP server: never reachable.
        assert!(!reachable_from(false, true, false, true, true));
        assert!(!reachable_from(false, false, true, true, true));
    }

    #[test]
    fn nothing_is_reachable_before_start() {
        // STATE is process-global; in this test binary nothing calls `start`.
        if STATE.get().is_none() {
            assert!(!mesh_reachable(true));
        }
    }

    /// Two netstacks over a WireGuard bridge: B forwards its listened port to a
    /// loopback echo server only when the gate says Forward.
    #[cfg(feature = "overlay-netstack")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn forwards_to_loopback_only_when_the_gate_says_so() {
        use std::net::{Ipv4Addr, SocketAddr};
        use std::sync::Arc;
        use std::time::Duration;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::UdpSocket;
        use tunnel_core::overlay::WgKeypair;
        use tunnel_core::overlay::bridge::run_bridge;
        use tunnel_core::overlay::netstack::Netstack;
        use tunnel_core::overlay::tun::TunIo;
        use tunnel_core::overlay::wg::{Carrier, WgDevice};

        // The local "RDP server": an echo on 127.0.0.1, whose port B listens on.
        let local = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let port = local.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = local.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 256];
                    while let Ok(n) = s.read(&mut buf).await {
                        if n == 0 || s.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });

        let a_ip = Ipv4Addr::new(100, 64, 0, 1);
        let b_ip = Ipv4Addr::new(100, 64, 0, 2);
        let (ka, kb) = (WgKeypair::generate(), WgKeypair::generate());
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
        let (dev_a, dev_b) = (Arc::new(dev_a), Arc::new(dev_b));
        let a = Netstack::start(a_ip, 10, 1280);
        let b = Netstack::start(b_ip, 10, 1280);
        tokio::spawn(run_bridge(a.tun.clone() as Arc<dyn TunIo>, dev_a, rx_a));
        tokio::spawn(run_bridge(b.tun.clone() as Arc<dyn TunIo>, dev_b, rx_b));

        // Gate by order: first connection Forward, second refused (opted out).
        let mut listener = b.handle.listen(port).await.unwrap();
        tokio::spawn(async move {
            for d in [Decision::Forward, Decision::RefuseOptedOut] {
                let Some(s) = listener.accept().await else {
                    return;
                };
                forward_one(s, port, d).await;
            }
        });

        let dst = SocketAddr::from((b_ip, port));
        let mut s = tokio::time::timeout(Duration::from_secs(20), async {
            loop {
                if let Ok(s) = a.handle.connect(dst).await {
                    break s;
                }
                tokio::time::sleep(Duration::from_millis(200)).await;
            }
        })
        .await
        .expect("connected over the WG bridge");
        s.write_all(b"rdp-bytes").await.unwrap();
        let mut got = [0u8; 9];
        tokio::time::timeout(Duration::from_secs(10), s.read_exact(&mut got))
            .await
            .expect("echo in time")
            .unwrap();
        assert_eq!(
            &got, b"rdp-bytes",
            "forwarded to the loopback server and back"
        );
        drop(s);

        // The refused connection carries nothing and is closed.
        let mut r = tokio::time::timeout(Duration::from_secs(10), a.handle.connect(dst))
            .await
            .expect("answered")
            .expect("accepted at TCP, then closed by the gate");
        let _ = r.write_all(b"x").await;
        let mut one = [0u8; 1];
        let read = tokio::time::timeout(Duration::from_secs(10), r.read(&mut one))
            .await
            .expect("closed in time");
        assert!(
            !matches!(read, Ok(n) if n > 0),
            "a refused connection is never forwarded: {read:?}"
        );
    }
}
