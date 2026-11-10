// SPDX-License-Identifier: MPL-2.0
// Copyright (C) 2026 G ROX EOOD
//! FR-110 — the carrier sockets ask for buffers the size of a burst.
//!
//! A carrier socket used to keep the OS default: 208 KB to receive on Linux.
//! A burst at line rate fills that in under 2 ms. The kernel then drops the
//! carrier's datagrams before the daemon reads them, and TCP inside the tunnel
//! reads each drop as congestion. Measured on an M2 Pro Linux host: 116–128
//! Mbit/s into it over the overlay, with +455 / +623 `RcvbufErrors` per 256
//! MiB at ~1% CPU. With a 4 MiB buffer and no other change, 520 Mbit/s and
//! none (#2350).
//!
//! What this module does, and does NOT do:
//!
//! - **Ask, never fail.** A socket whose OS refuses every size keeps working
//!   on the default, and says so.
//! - **Force on Linux.** `SO_RCVBUF` is capped by `net.core.rmem_max`, which is
//!   212992 on most distributions, so the plain option would change nothing
//!   where it matters most. The daemon runs as root, which may use the FORCE
//!   options past the cap. Without `CAP_NET_ADMIN` they are refused, and the
//!   capped plain option is the fallback.
//! - **Step down elsewhere.** macOS refuses a size above `kern.ipc.maxsockbuf`
//!   outright (`ENOBUFS`) instead of capping it. Windows takes the size.
//! - **Touch carrier sockets only.** It is called from the one seam that binds
//!   them ([`super::direct::bind_direct_socket`]). Never the MagicDNS resolver,
//!   or any other socket.

use socket2::SockRef;
use tokio::net::UdpSocket;

/// What a carrier socket asks for, receive and send: wireguard-go's and
/// Tailscale's size. 4 MiB already removed every drop in #2350's experiment.
pub(crate) const CARRIER_SOCKBUF: usize = 7 << 20;

/// Below this the receive grant counts as degraded and is said at WARN: #2350
/// measured drops at 208 KB and none at 4 MiB.
const DEGRADED_BELOW: usize = 1 << 20;

/// FR-110 kill switch `MESHHARBORD_OVERLAY_SOCKBUF=0`: the OS default, as before
/// FR-110.
pub(crate) fn enabled() -> bool {
    crate::env::flag("OVERLAY_SOCKBUF", true)
}

/// How one direction's request ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Grant {
    /// Linux `SO_RCVBUFFORCE` / `SO_SNDBUFFORCE`, past `net.core.*mem_max`.
    /// Only Linux has FORCE options, so only Linux builds this.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    Forced,
    /// The plain option: what the OS's cap allows (Linux caps silently).
    Plain,
    /// Every size was refused; the OS default stands.
    Default,
}

/// One carrier socket's buffers, as the OS reports them after the request.
/// Linux reports twice what was asked, for its own bookkeeping.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Tuned {
    pub recv: usize,
    pub send: usize,
    pub recv_how: Grant,
    pub send_how: Grant,
}

/// The sizes the plain option tries, largest first. macOS refuses a size above
/// its cap instead of capping it, so the request steps down.
fn steps(want: usize) -> impl Iterator<Item = usize> {
    std::iter::once(want).chain(
        [4usize << 20, 2 << 20, 1 << 20]
            .into_iter()
            .filter(move |s| *s < want),
    )
}

#[derive(Clone, Copy)]
enum Dir {
    Recv,
    Send,
}

/// Linux's FORCE options: past `net.core.rmem_max` / `wmem_max`, for a
/// process holding `CAP_NET_ADMIN` (the daemon as root).
#[cfg(target_os = "linux")]
fn force(sock: &UdpSocket, dir: Dir, size: usize) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    let opt = match dir {
        Dir::Recv => libc::SO_RCVBUFFORCE,
        Dir::Send => libc::SO_SNDBUFFORCE,
    };
    let value = libc::c_int::try_from(size).unwrap_or(libc::c_int::MAX);
    // SAFETY: the fd is open for the call (`sock` is borrowed), and the option
    // value is a `c_int` passed with its own size, as SOL_SOCKET expects.
    let rc = unsafe {
        libc::setsockopt(
            sock.as_raw_fd(),
            libc::SOL_SOCKET,
            opt,
            (&value as *const libc::c_int).cast(),
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        )
    };
    if rc == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

fn ask(sock: &UdpSocket, dir: Dir, want: usize) -> Grant {
    #[cfg(target_os = "linux")]
    if force(sock, dir, want).is_ok() {
        return Grant::Forced;
    }
    let s = SockRef::from(sock);
    for size in steps(want) {
        let ok = match dir {
            Dir::Recv => s.set_recv_buffer_size(size),
            Dir::Send => s.set_send_buffer_size(size),
        };
        if ok.is_ok() {
            return Grant::Plain;
        }
    }
    Grant::Default
}

/// Ask for `want` in both directions and read back what the OS granted.
pub(crate) fn tune(sock: &UdpSocket, want: usize) -> Tuned {
    let recv_how = ask(sock, Dir::Recv, want);
    let send_how = ask(sock, Dir::Send, want);
    let s = SockRef::from(sock);
    Tuned {
        recv: s.recv_buffer_size().unwrap_or(0),
        send: s.send_buffer_size().unwrap_or(0),
        recv_how,
        send_how,
    }
}

/// The seam's call: tune a freshly bound carrier socket unless the kill switch
/// says not to, and say once what it got.
pub(crate) fn tune_carrier(sock: &UdpSocket, what: &'static str) {
    let local = sock.local_addr().map(|a| a.to_string()).unwrap_or_default();
    if !enabled() {
        tracing::info!(
            what,
            %local,
            "overlay: carrier socket buffers left at the OS default (MESHHARBORD_OVERLAY_SOCKBUF=0, FR-110)"
        );
        return;
    }
    let t = tune(sock, CARRIER_SOCKBUF);
    if t.recv < DEGRADED_BELOW {
        tracing::warn!(
            what, %local, recv = t.recv, send = t.send,
            recv_how = ?t.recv_how, send_how = ?t.send_how,
            "overlay: the OS kept this carrier socket's receive buffer small; TCP over the overlay \
             may drop under bursts (FR-110: run the daemon as root, or raise net.core.rmem_max)"
        );
    } else {
        tracing::info!(
            what, %local, recv = t.recv, send = t.send,
            recv_how = ?t.recv_how, send_how = ?t.send_how,
            "overlay: carrier socket buffers (FR-110; MESHHARBORD_OVERLAY_SOCKBUF=0 keeps the OS default)"
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn bound() -> UdpSocket {
        UdpSocket::bind("127.0.0.1:0")
            .await
            .expect("a loopback socket")
    }

    /// The plain option tries the request, then 4, 2 and 1 MiB, largest first,
    /// and never anything above the request.
    #[test]
    fn the_request_steps_down_and_never_up() {
        assert_eq!(
            steps(7 << 20).collect::<Vec<_>>(),
            vec![7 << 20, 4 << 20, 2 << 20, 1 << 20]
        );
        assert_eq!(steps(1 << 20).collect::<Vec<_>>(), vec![1 << 20]);
        assert_eq!(
            steps(3 << 20).collect::<Vec<_>>(),
            vec![3 << 20, 2 << 20, 1 << 20]
        );
    }

    /// Whatever the OS allows this test (CI is no root on Linux, so FORCE is
    /// refused there and the capped plain option answers), the request is
    /// accepted, and the socket ends with at least the buffers it started with.
    #[tokio::test]
    async fn a_carrier_socket_asks_and_never_ends_smaller() {
        let sock = bound().await;
        let (recv0, send0) = {
            let s = SockRef::from(&sock);
            (s.recv_buffer_size().unwrap(), s.send_buffer_size().unwrap())
        };
        let t = tune(&sock, 1 << 20);
        assert_ne!(
            t.recv_how,
            Grant::Default,
            "the receive request was refused"
        );
        assert_ne!(t.send_how, Grant::Default, "the send request was refused");
        assert!(
            t.recv >= recv0,
            "receive buffer shrank: {recv0} -> {}",
            t.recv
        );
        assert!(t.send >= send0, "send buffer shrank: {send0} -> {}", t.send);
    }

    /// As root on Linux, the FORCE options get the whole request past
    /// `net.core.rmem_max` / `wmem_max`, whatever the distribution set them to.
    /// Linux reports twice what was asked. It needs root, which CI does not
    /// have, so it is ignored there; run it as root on a Linux host:
    /// `sudo <test binary> --ignored as_root_linux_forces_past_the_cap`.
    /// A run without root fails rather than passing on nothing.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "needs root on Linux"]
    async fn as_root_linux_forces_past_the_cap() {
        // SAFETY: geteuid has no preconditions and cannot fail.
        assert_eq!(unsafe { libc::geteuid() }, 0, "run this test as root");
        let sock = bound().await;
        let t = tune(&sock, CARRIER_SOCKBUF);
        assert_eq!((t.recv_how, t.send_how), (Grant::Forced, Grant::Forced));
        assert!(t.recv >= 2 * CARRIER_SOCKBUF, "receive buffer {}", t.recv);
        assert!(t.send >= 2 * CARRIER_SOCKBUF, "send buffer {}", t.send);
    }

    /// A tuned socket still carries datagrams both ways.
    #[tokio::test]
    async fn a_tuned_socket_still_carries_datagrams() {
        let a = bound().await;
        let b = bound().await;
        tune(&a, CARRIER_SOCKBUF);
        tune(&b, CARRIER_SOCKBUF);
        a.send_to(b"ping", b.local_addr().unwrap()).await.unwrap();
        let mut buf = [0u8; 16];
        let (n, from) = b.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"ping");
        b.send_to(b"pong", from).await.unwrap();
        let (n, _) = a.recv_from(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"pong");
    }
}
